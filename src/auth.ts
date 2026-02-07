import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmdirSync,
  unlinkSync,
} from "node:fs";
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import { getRaycastDataDir } from "./raycast-paths.js";
import { resolveSqlcipherPath } from "./sqlcipher.js";

const RAYCAST_SALT = "yvkwWXzxPPBAqY2tmaKrB*DvYjjMaeEf";

type SqlcipherInitSql = string;
type SqlcipherKeyExpr = string;
type SqlcipherKeyPragma = "key" | "hexkey";

interface SqlcipherOpenConfig {
  initSql: SqlcipherInitSql;
  keyPragma: SqlcipherKeyPragma;
  keyExpr: SqlcipherKeyExpr;
}

interface KeyCandidate {
  keyPragma: SqlcipherKeyPragma;
  keyExpr: SqlcipherKeyExpr;
  label: string;
}

interface InitCandidate {
  initSql: SqlcipherInitSql;
  label: string;
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresIn?: number;
  updatedAt?: string;
  id?: string;
  providerId?: string;
  scope?: string;
  tokenType?: string;
}

let cachedSqlcipherPath: string | null = null;
let cachedOpenConfig: SqlcipherOpenConfig | null = null;
let cachedExtensionsDb: string | null = null;

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function sha256HexBytes(...parts: Buffer[]): string {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest("hex");
}

function sqlStringLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function trimNulls(value: string): string {
  return value.replace(/\0+$/g, "").trim();
}

function isPrintableAscii(value: string): boolean {
  // Avoid feeding arbitrary binary garbage into PRAGMA key as a string candidate.
  return /^[\x20-\x7E]+$/.test(value);
}

function tryDecodeBase64(value: string): Buffer | null {
  const raw = value.trim();
  if (!raw) return null;

  // Allow base64 or base64url, with optional padding.
  const looksB64 = /^[A-Za-z0-9+/]+={0,2}$/.test(raw);
  const looksB64Url = /^[A-Za-z0-9_-]+={0,2}$/.test(raw);
  if (!looksB64 && !looksB64Url) return null;
  if (raw.length % 4 === 1) return null;

  let normalized = raw;
  if (looksB64Url && !looksB64) {
    normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
  }
  const mod = normalized.length % 4;
  if (mod === 2) normalized += "==";
  else if (mod === 3) normalized += "=";
  else if (mod !== 0) return null;

  try {
    const bytes = Buffer.from(normalized, "base64");
    return bytes.length > 0 ? bytes : null;
  } catch {
    return null;
  }
}

async function getSqlcipherPath(): Promise<string> {
  if (cachedSqlcipherPath) return cachedSqlcipherPath;
  cachedSqlcipherPath = await resolveSqlcipherPath();
  return cachedSqlcipherPath;
}

function sleepSync(ms: number) {
  if (typeof Bun !== "undefined" && Bun.sleepSync) {
    Bun.sleepSync(ms);
    return;
  }
  const start = Date.now();
  while (Date.now() - start < ms) {
    // Busy wait fallback
  }
}

function getMacKeyCandidates(): KeyCandidate[] {
  const envKey = process.env.RAYBRIDGE_RAYCAST_DB_KEY;
  if (envKey && envKey.trim().length > 0) {
    return [
      {
        keyPragma: "key",
        keyExpr: sqlStringLiteral(envKey.trim()),
        label: "env:RAYBRIDGE_RAYCAST_DB_KEY",
      },
    ];
  }

  const keyHex = execFileSync(
    "security",
    [
      "find-generic-password",
      "-s",
      "Raycast",
      "-a",
      "database_key",
      "-w",
    ],
    { encoding: "utf-8" }
  ).trim();

  const passphrase = sha256Hex(keyHex + RAYCAST_SALT);
  return [
    {
      keyPragma: "key",
      keyExpr: sqlStringLiteral(passphrase),
      label: "mac:keychain sha256(keyHex+salt)",
    },
  ];
}

function encodePowerShell(script: string): string {
  // PowerShell expects UTF-16LE for -EncodedCommand.
  return Buffer.from(script, "utf16le").toString("base64");
}

function readWindowsCredentialBlob(target: string): Buffer | null {
  const ps = `
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$target = '${target.replace(/'/g, "''")}'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CredProbe {
  [StructLayout(LayoutKind.Sequential)]
  public struct FILETIME {
    public UInt32 dwLowDateTime;
    public UInt32 dwHighDateTime;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public UInt32 Flags;
    public UInt32 Type;
    public string TargetName;
    public string Comment;
    public FILETIME LastWritten;
    public UInt32 CredentialBlobSize;
    public IntPtr CredentialBlob;
    public UInt32 Persist;
    public UInt32 AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
  }

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern void CredFree(IntPtr cred);

  public static byte[] ReadBlob(string target) {
    IntPtr p;
    if (!CredRead(target, 1, 0, out p)) return null;
    try {
      var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
      if (c.CredentialBlob == IntPtr.Zero || c.CredentialBlobSize == 0) return new byte[0];
      var b = new byte[c.CredentialBlobSize];
      Marshal.Copy(c.CredentialBlob, b, 0, b.Length);
      return b;
    } finally {
      CredFree(p);
    }
  }
}
"@

$blob = [CredProbe]::ReadBlob($target)
if ($null -eq $blob) { exit 2 }
[Convert]::ToBase64String($blob)
`.trim();

  try {
    const out = execFileSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(ps)],
      { encoding: "utf-8" }
    ).trim();
    if (!out) return null;
    return Buffer.from(out, "base64");
  } catch {
    return null;
  }
}

function getWindowsKeyCandidates(): KeyCandidate[] {
  const candidates: KeyCandidate[] = [];

  const add = (label: string, keyPragma: SqlcipherKeyPragma, keyExpr: string) => {
    candidates.push({ label, keyPragma, keyExpr });
  };
  const addKey = (label: string, passphrase: string) =>
    add(label, "key", sqlStringLiteral(passphrase));
  const addHexkey = (label: string, hex: string) =>
    add(label, "hexkey", sqlStringLiteral(hex.toLowerCase()));

  const addFromHex = (label: string, hex: string) => {
    const h = hex.toLowerCase();
    if (!h) return;

    // Interpret the hex string as a normal passphrase string.
    addKey(`${label}:key(passphrase-hex)`, h);
    addKey(`${label}:key(sha256(hex+salt))`, sha256Hex(h + RAYCAST_SALT));

    // Interpret the underlying bytes as the passphrase (binary key).
    addHexkey(`${label}:hexkey(binary-passphrase)`, h);

    // Interpret as raw key material (no KDF). Only meaningful for 32-byte key (64 hex chars)
    // or 32-byte key + 16-byte salt (96 hex chars).
    if (h.length === 64 || h.length === 96) {
      addKey(`${label}:key(raw-x)`, `x'${h}'`);
      addKey(`${label}:key(raw)`, `raw:${h}`);
    }
  };

  const envKey = process.env.RAYBRIDGE_RAYCAST_DB_KEY;
  if (envKey && envKey.trim().length > 0) {
    addKey("env:RAYBRIDGE_RAYCAST_DB_KEY", envKey.trim());
  }

  // Raycast for Windows writes a key file under %LOCALAPPDATA%\Raycast\last_key.
  try {
    const lastKeyPath = join(getRaycastDataDir(), "last_key");
    if (existsSync(lastKeyPath)) {
      const lastKeyBytes = readFileSync(lastKeyPath);

      const lastKeyUtf8 = trimNulls(lastKeyBytes.toString("utf8"));
      if (lastKeyUtf8 && isPrintableAscii(lastKeyUtf8)) {
        addKey("last_key:utf8", lastKeyUtf8);
        addKey(
          "last_key:utf8:sha256(+salt)",
          sha256Hex(lastKeyUtf8 + RAYCAST_SALT)
        );

        if (/^[0-9a-fA-F]+$/.test(lastKeyUtf8) && lastKeyUtf8.length % 2 === 0) {
          addFromHex("last_key:utf8-hex", lastKeyUtf8);
        }
      }

      addFromHex("last_key:bytes", lastKeyBytes.toString("hex"));
      addKey(
        "last_key:bytes:sha256(bytes+salt)",
        sha256HexBytes(lastKeyBytes, Buffer.from(RAYCAST_SALT, "utf8"))
      );

      if (lastKeyBytes.length >= 32) {
        addFromHex(
          "last_key:bytes:first32",
          lastKeyBytes.subarray(0, 32).toString("hex")
        );
      }
      if (lastKeyBytes.length >= 48) {
        addFromHex(
          "last_key:bytes:first48",
          lastKeyBytes.subarray(0, 48).toString("hex")
        );
      }

      const lastKeyB64 = lastKeyBytes.toString("base64");
      if (lastKeyB64) {
        addKey("last_key:bytes:base64", lastKeyB64);
        addKey(
          "last_key:bytes:sha256(b64+salt)",
          sha256Hex(lastKeyB64 + RAYCAST_SALT)
        );
      }
    }
  } catch {
    // ignore
  }

  // Credential Manager entry observed on Windows:
  //   Target: LegacyGeneric:target=Raycast-Production/BackendDBKey
  const targets = [
    "Raycast-Production/BackendDBKey",
    "LegacyGeneric:target=Raycast-Production/BackendDBKey",
    "Raycast-Canary/BackendDBKey",
    "LegacyGeneric:target=Raycast-Canary/BackendDBKey",
  ];

  for (const target of targets) {
    const blob = readWindowsCredentialBlob(target);
    if (!blob) continue;

    addFromHex(`cred:${target}:bytes`, blob.toString("hex"));
    addKey(
      `cred:${target}:bytes:sha256(bytes+salt)`,
      sha256HexBytes(blob, Buffer.from(RAYCAST_SALT, "utf8"))
    );

    if (blob.length >= 32) {
      addFromHex(
        `cred:${target}:bytes:first32`,
        blob.subarray(0, 32).toString("hex")
      );
    }
    if (blob.length >= 48) {
      addFromHex(
        `cred:${target}:bytes:first48`,
        blob.subarray(0, 48).toString("hex")
      );
    }

    const utf8 = trimNulls(blob.toString("utf8"));
    if (utf8 && isPrintableAscii(utf8)) {
      addKey(`cred:${target}:utf8`, utf8);
      addKey(
        `cred:${target}:utf8:sha256(+salt)`,
        sha256Hex(utf8 + RAYCAST_SALT)
      );

      // If the credential blob itself is a base64/base64url string, decode it and treat as raw key material.
      const decoded = tryDecodeBase64(utf8);
      if (decoded) {
        addFromHex(
          `cred:${target}:utf8:base64-decoded`,
          decoded.toString("hex")
        );
        addKey(
          `cred:${target}:utf8:base64-decoded:sha256(bytes+salt)`,
          sha256HexBytes(decoded, Buffer.from(RAYCAST_SALT, "utf8"))
        );
        if (decoded.length >= 32) {
          addFromHex(
            `cred:${target}:utf8:base64-decoded:first32`,
            decoded.subarray(0, 32).toString("hex")
          );
        }
        if (decoded.length >= 48) {
          addFromHex(
            `cred:${target}:utf8:base64-decoded:first48`,
            decoded.subarray(0, 48).toString("hex")
          );
        }
      }
    }

    const utf16 = trimNulls(blob.toString("utf16le"));
    if (utf16 && isPrintableAscii(utf16)) {
      addKey(`cred:${target}:utf16le`, utf16);
      addKey(
        `cred:${target}:utf16le:sha256(+salt)`,
        sha256Hex(utf16 + RAYCAST_SALT)
      );
    }

    const b64 = blob.toString("base64");
    if (b64) {
      addKey(`cred:${target}:bytes:base64`, b64);
      addKey(
        `cred:${target}:bytes:base64:sha256(+salt)`,
        sha256Hex(b64 + RAYCAST_SALT)
      );
    }
  }

  // De-dup while preserving order.
  const seen = new Set<string>();
  return candidates.filter((c) => {
    const k = `${c.keyPragma}:${c.keyExpr}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function getKeyCandidates(): KeyCandidate[] {
  if (process.platform === "win32") return getWindowsKeyCandidates();
  return getMacKeyCandidates();
}

function getInitCandidates(): InitCandidate[] {
  const out: InitCandidate[] = [];
  const add = (label: string, initSql: string) => out.push({ label, initSql });

  // SQLCipher scheme (try common compatibility/legacy modes).
  const sqlcipher = "PRAGMA cipher = 'sqlcipher';\n";
  add("sqlcipher", sqlcipher);
  add("sqlcipher:legacy4", `${sqlcipher}PRAGMA legacy = 4;\n`);
  add("sqlcipher:legacy3", `${sqlcipher}PRAGMA legacy = 3;\n`);
  add("sqlcipher:legacy2", `${sqlcipher}PRAGMA legacy = 2;\n`);
  add("sqlcipher:legacy1", `${sqlcipher}PRAGMA legacy = 1;\n`);

  // Default cipher scheme (SQLite3MultipleCiphers default is sqleet:ChaCha20).
  add("default", "");
  add("chacha20", "PRAGMA cipher = 'chacha20';\n");
  add("chacha20:legacy1", "PRAGMA cipher = 'chacha20';\nPRAGMA legacy = 1;\n");

  // WAL encryption legacy mode (older SQLite3MC versions).
  add("default:legacywal", "PRAGMA mc_legacy_wal = 1;\n");
  add(
    "chacha20:legacywal",
    "PRAGMA mc_legacy_wal = 1;\nPRAGMA cipher = 'chacha20';\n"
  );
  add(
    "sqlcipher:legacywal",
    "PRAGMA mc_legacy_wal = 1;\nPRAGMA cipher = 'sqlcipher';\n"
  );

  // De-dup while preserving order.
  const seen = new Set<string>();
  return out.filter((c) => {
    if (seen.has(c.initSql)) return false;
    seen.add(c.initSql);
    return true;
  });
}

function listRaycastDbFiles(dataDir: string): string[] {
  if (process.platform === "darwin") {
    return [join(dataDir, "raycast-enc.sqlite")];
  }

  let entries: string[];
  try {
    entries = readdirSync(dataDir);
  } catch {
    return [];
  }

  const files: string[] = [];
  for (const name of entries) {
    if (name.endsWith("-wal") || name.endsWith("-shm")) continue;
    if (name.endsWith(".db") || name.endsWith(".sqlite") || name.endsWith(".sqlite3")) {
      files.push(join(dataDir, name));
    }
  }

  // Prefer the primary DBs first.
  const preferred = ["main.db", "settings_v2.db", "settings.db", "raycast-enc.sqlite"];
  files.sort((a, b) => {
    const ai = preferred.indexOf(basename(a));
    const bi = preferred.indexOf(basename(b));
    const aRank = ai >= 0 ? ai : preferred.length + 1;
    const bRank = bi >= 0 ? bi : preferred.length + 1;
    return aRank - bRank;
  });

  return files;
}

function runSqlcipherQuery(
  sqlcipherPath: string,
  dbPath: string,
  openConfig: SqlcipherOpenConfig,
  sql: string,
  retries = 3
): any[] {
  const stripShellPreamble = (out: string): string => {
    // Some shells (notably SQLite3MultipleCiphers) print "ok" for PRAGMA key/cipher/legacy lines.
    // We run multiple PRAGMAs before the actual query, so we may have multiple leading ok lines
    // before the JSON output from the SELECT.
    let s = out ?? "";
    // Normalize to simplify matching; keep original content for JSON portion.
    s = s.replace(/^(?:\s*ok\s*\r?\n)+/i, "");
    s = s.trimStart();

    // If there is any other preamble, try to locate the beginning of JSON.
    if (s.length > 0 && s[0] !== "[" && s[0] !== "{") {
      const idx = s.search(/[\[{]/);
      if (idx >= 0) s = s.slice(idx);
    }

    return s.trim();
  };

  const tmpDir = mkdtempSync(join(tmpdir(), "raybridge-db-"));
  const tmpDb = join(tmpDir, basename(dbPath));

  const cleanup = () => {
    for (const ext of ["", "-wal", "-shm"]) {
      try {
        unlinkSync(tmpDb + ext);
      } catch {
        // Ignore cleanup errors
      }
    }
    try {
      rmdirSync(tmpDir);
    } catch {
      // Ignore cleanup errors
    }
  };

  for (let attempt = 1; attempt <= retries; attempt++) {
    let targetDb = tmpDb;

    try {
      // Copy DB/WAL/SHM for stable reads.
      // On Windows the files may be locked; fall back to querying the original path.
      try {
        copyFileSync(dbPath, tmpDb);
        for (const ext of ["-wal", "-shm"]) {
          const src = dbPath + ext;
          if (existsSync(src)) copyFileSync(src, tmpDb + ext);
        }
      } catch {
        targetDb = dbPath;
      }

      const input = `${openConfig.initSql}PRAGMA ${openConfig.keyPragma} = ${openConfig.keyExpr};\n.mode json\n${sql}`;
      const proc = spawnSync(sqlcipherPath, [targetDb], {
        input,
        encoding: "utf-8",
        maxBuffer: 10 * 1024 * 1024,
        timeout: 3000,
      });
      if (proc.error) throw proc.error;
      if (typeof proc.status === "number" && proc.status !== 0) {
        const err: any = new Error(`sqlcipher exited with code ${proc.status}`);
        err.stdout = proc.stdout;
        err.stderr = proc.stderr;
        throw err;
      }
      if (proc.signal) {
        const err: any = new Error(`sqlcipher exited due to signal ${proc.signal}`);
        err.stdout = proc.stdout;
        err.stderr = proc.stderr;
        throw err;
      }
      const result = String(proc.stdout || "");

      cleanup();

      const jsonStr = stripShellPreamble(result);
      try {
        return JSON.parse(jsonStr.trim());
      } catch {
        return [];
      }
    } catch (err: any) {
      const message = [err?.message, err?.stderr, err?.stdout]
        .filter(Boolean)
        .join("\n");
      const isTransient =
        message.includes("database is locked") ||
        message.includes("database disk image is malformed") ||
        message.includes("no such table");

      if (isTransient && attempt < retries) {
        sleepSync(50 * attempt);
        continue;
      }

      cleanup();
      throw err;
    }
  }

  cleanup();
  return [];
}

async function getWorkingOpenConfig(
  sqlcipherPath: string,
  dataDir: string
): Promise<SqlcipherOpenConfig> {
  if (cachedOpenConfig) return cachedOpenConfig;

  const dbs = listRaycastDbFiles(dataDir).filter((p) => existsSync(p));
  if (dbs.length === 0) {
    throw new Error(`No Raycast database files found in ${dataDir}`);
  }

  const keyCandidates = getKeyCandidates();
  if (keyCandidates.length === 0) {
    throw new Error("No Raycast DB key candidates found");
  }

  const initCandidates = getInitCandidates();
  const probeDbs = dbs.slice(0, Math.min(dbs.length, 4));

  const debug = process.env.RAYBRIDGE_DEBUG_DB_OPEN === "1";
  if (debug) {
    console.log(
      `raybridge: probing Raycast DB open: dbs=${probeDbs
        .map((p) => basename(p))
        .join(", ")}`
    );
    console.log(
      `raybridge: init candidates=${initCandidates.length}, key candidates=${keyCandidates.length}`
    );
    let keyCount = 0;
    let hexkeyCount = 0;
    for (const k of keyCandidates) {
      if (k.keyPragma === "hexkey") hexkeyCount++;
      else keyCount++;
    }
    console.log(
      `raybridge: key candidate pragmas: key=${keyCount}, hexkey=${hexkeyCount}`
    );
    console.log(
      `raybridge: probe attempts (max)=${initCandidates.length * keyCandidates.length * probeDbs.length}`
    );
  }

  const errorCounts = new Map<string, number>();
  const incErr = (k: string) => errorCounts.set(k, (errorCounts.get(k) || 0) + 1);

  let attempt = 0;
  const totalAttempts = initCandidates.length * keyCandidates.length * probeDbs.length;

  for (let initIdx = 0; initIdx < initCandidates.length; initIdx++) {
    const init = initCandidates[initIdx];
    if (debug) {
      console.log(`raybridge: trying init ${initIdx + 1}/${initCandidates.length}: ${init.label}`);
    }

    for (let keyIdx = 0; keyIdx < keyCandidates.length; keyIdx++) {
      const key = keyCandidates[keyIdx];
      if (debug && (keyIdx === 0 || (keyIdx + 1) % 10 === 0)) {
        console.log(`raybridge: init ${init.label}: key progress ${keyIdx + 1}/${keyCandidates.length}`);
      }

      for (const testDb of probeDbs) {
        attempt++;
        if (debug && attempt % 200 === 0) {
          console.log(`raybridge: probe progress ${attempt}/${totalAttempts} (latest db=${basename(testDb)})`);
        }

        const openConfig: SqlcipherOpenConfig = {
          initSql: init.initSql,
          keyPragma: key.keyPragma,
          keyExpr: key.keyExpr,
        };

        try {
          const probe = runSqlcipherQuery(
            sqlcipherPath,
            testDb,
            openConfig,
            "SELECT count(*) AS c FROM sqlite_master;"
          );
          if (!Array.isArray(probe) || probe.length === 0) {
            incErr("probe_empty");
            continue;
          }

          cachedOpenConfig = openConfig;
          if (debug) {
            console.log(
              `raybridge: open OK (init=${init.label}, key=${key.label}, pragma=${key.keyPragma}, db=${basename(
                testDb
              )})`
            );
          }
          return cachedOpenConfig;
        } catch (err: any) {
          const msg = [err?.message, err?.stderr, err?.stdout]
            .filter(Boolean)
            .join("\n")
            .toLowerCase();

          if (msg.includes("file is not a database")) incErr("not_a_database");
          else if (msg.includes("database is locked")) incErr("locked");
          else if (msg.includes("etimedout") || msg.includes("timed out")) incErr("timeout");
          else if (msg.includes("syntax error")) incErr("syntax");
          else if (msg.includes("malformed")) incErr("malformed");
          else incErr("other");
          continue;
        }
      }
    }
  }

  if (debug) {
    const top = Array.from(errorCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
    console.log(
      `raybridge: open probe failed; error summary: ${top
        .map(([k, v]) => `${k}=${v}`)
        .join(", ")}`
    );
  }

  throw new Error("Could not open Raycast DB with any known key candidate");
}

async function getExtensionsDbPath(
  sqlcipherPath: string,
  dataDir: string,
  openConfig: SqlcipherOpenConfig
): Promise<string> {
  if (cachedExtensionsDb) return cachedExtensionsDb;

  const dbs = listRaycastDbFiles(dataDir).filter((p) => existsSync(p));
  for (const dbPath of dbs) {
    try {
      const cols = runSqlcipherQuery(
        sqlcipherPath,
        dbPath,
        openConfig,
        "PRAGMA table_info(extensions);"
      );

      const colNames = new Set<string>();
      for (const row of cols) {
        if (row && typeof row.name === "string") colNames.add(row.name);
      }

      if (colNames.has("tokenSets") || colNames.has("preferences")) {
        cachedExtensionsDb = dbPath;
        return dbPath;
      }
    } catch {
      continue;
    }
  }

  throw new Error(
    `Could not locate Raycast extensions table in any DB under ${dataDir}`
  );
}

/**
 * Load OAuth token sets for all extensions from Raycast's encrypted DB.
 * Returns a map of extension name -> array of token sets.
 */
export async function loadRaycastTokens(): Promise<Map<string, TokenSet[]>> {
  const tokens = new Map<string, TokenSet[]>();

  try {
    const dataDir = getRaycastDataDir();
    const dbFiles = listRaycastDbFiles(dataDir).filter((p) => existsSync(p));
    if (dbFiles.length === 0) return tokens;

    const sqlcipherPath = await getSqlcipherPath();
    const openConfig = await getWorkingOpenConfig(sqlcipherPath, dataDir);
    const dbPath = await getExtensionsDbPath(sqlcipherPath, dataDir, openConfig);

    const rows = runSqlcipherQuery(
      sqlcipherPath,
      dbPath,
      openConfig,
      "SELECT name, tokenSets FROM extensions WHERE tokenSets IS NOT NULL AND tokenSets != '';"
    );

    for (const row of rows) {
      if (!row?.name || !row?.tokenSets) continue;
      try {
        const parsed = JSON.parse(row.tokenSets);
        const sets = Array.isArray(parsed) ? parsed : [parsed];
        tokens.set(row.name, sets as TokenSet[]);
      } catch {
        continue;
      }
    }
  } catch (err) {
    console.error("raybridge: Could not read Raycast OAuth tokens:", err);
  }

  return tokens;
}

/**
 * Load extension preferences from Raycast's encrypted DB.
 * Returns a map of extension name -> preference key-value pairs.
 */
export async function loadRaycastPreferences(): Promise<
  Record<string, Record<string, unknown>>
> {
  const prefs: Record<string, Record<string, unknown>> = {};

  try {
    const dataDir = getRaycastDataDir();
    const dbFiles = listRaycastDbFiles(dataDir).filter((p) => existsSync(p));
    if (dbFiles.length === 0) return prefs;

    const sqlcipherPath = await getSqlcipherPath();
    const openConfig = await getWorkingOpenConfig(sqlcipherPath, dataDir);
    const dbPath = await getExtensionsDbPath(sqlcipherPath, dataDir, openConfig);

    const rows = runSqlcipherQuery(
      sqlcipherPath,
      dbPath,
      openConfig,
      "SELECT name, preferences FROM extensions WHERE preferences IS NOT NULL AND preferences != '';"
    );

    for (const row of rows) {
      if (!row?.name || !row?.preferences) continue;
      try {
        const parsed = JSON.parse(row.preferences);

        // Preferences are stored as array of {name, value, ...} objects
        const prefObj: Record<string, unknown> = {};
        if (Array.isArray(parsed)) {
          for (const pref of parsed) {
            if (pref?.name && pref.value !== undefined) {
              prefObj[pref.name] = pref.value;
            }
          }
        }

        if (Object.keys(prefObj).length > 0) {
          prefs[row.name] = prefObj;
        }
      } catch {
        continue;
      }
    }
  } catch (err) {
    console.error("raybridge: Could not read Raycast preferences:", err);
  }

  return prefs;
}
