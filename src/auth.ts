import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createDecipheriv, createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { getRaycastDataDir } from "./raycast-paths.js";
import { resolveSqlcipherPath } from "./sqlcipher.js";
import { resolveWindowsPowerShellExe } from "./windows-exe.js";

const RAYCAST_SALT = "yvkwWXzxPPBAqY2tmaKrB*DvYjjMaeEf";

type SqlcipherInitSql = string;
type SqlcipherKeyExpr = string;
type SqlcipherKeyPragma = "key" | "hexkey";

interface SqlcipherOpenConfig {
  initSql: SqlcipherInitSql;
  keyPragma: SqlcipherKeyPragma;
  keyExpr: SqlcipherKeyExpr;
  /** When set, DB is encrypted at file level (AES-256-CBC); decrypt to temp then open with vanilla SQLite. */
  transparentDecryptKey?: Buffer;
}

const SQLITE_HEADER = Buffer.from("SQLite format 3\0", "utf8");
const AES_BLOCK = 16;
const GCM_TAG = 16;

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

let cachedWindowsDataDump:
  | { atMs: number; tokens: Map<string, TokenSet[]>; prefs: Record<string, Record<string, unknown>> }
  | null = null;
let warnedWindowsBackendKeyMissing = false;

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

const WINDOWS_CREDENTIAL_TARGETS = [
  "Raycast-Production/BackendDBKey",
  "LegacyGeneric:target=Raycast-Production/BackendDBKey",
  "Raycast-Canary/BackendDBKey",
  "LegacyGeneric:target=Raycast-Canary/BackendDBKey",
  // Canary Windows-specific targets (from cmdkey /list).
  "canaryWindowsEncKey",
  "LegacyGeneric:target=canaryWindowsEncKey",
  "canaryWindowsKey",
  "LegacyGeneric:target=canaryWindowsKey",
  "canaryWindowsHmakKey",
  "LegacyGeneric:target=canaryWindowsHmakKey",
] as const;

function getWindowsCredentialTargets(): readonly string[] {
  return WINDOWS_CREDENTIAL_TARGETS;
}

function readWindowsCredentialBlob(target: string): Buffer | null {
  const psExe = resolveWindowsPowerShellExe();
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
      psExe,
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

  const addRawKeyHex = (label: string, hex: string) => {
    const h = hex.toLowerCase();
    if (!h) return;

    // SQLCipher raw key forms:
    // - PRAGMA key = x'<hex>';           (blob literal)
    // - PRAGMA key = "x'<hex>'";         (string wrapper accepted by some shells/builds)
    //
    // SQLite3MultipleCiphers also accepts raw:<hex> in a string.
    add(`${label}:key(raw-blob-literal)`, "key", `x'${h}'`);
    add(`${label}:key(raw-string-x)`, "key", `"x'${h}'"`);
    addKey(`${label}:key(raw-colon)`, `raw:${h}`);
  };

  const addFromHex = (label: string, hex: string) => {
    const h = hex.toLowerCase();
    if (!h) return;

    // Interpret the hex string as a normal passphrase string.
    addKey(`${label}:key(passphrase-hex)`, h);
    addKey(`${label}:key(sha256(hex+salt))`, sha256Hex(h + RAYCAST_SALT));
    addKey(`${label}:key(sha256(salt+hex))`, sha256Hex(RAYCAST_SALT + h));
    addKey(`${label}:key(sha256(hex))`, sha256Hex(h));

    // Interpret the underlying bytes as the passphrase (binary key).
    addHexkey(`${label}:hexkey(binary-passphrase)`, h);

    // Interpret as raw key material (no KDF). Only meaningful for 32-byte key (64 hex chars),
    // 32-byte key + 16-byte salt (96 hex chars), or 64-byte key (128 hex chars).
    if (h.length === 64 || h.length === 96) {
      addRawKeyHex(label, h);
    }
    if (h.length === 128) {
      // 64-byte (512-bit) raw key — some Windows Raycast builds may use full credential/blob as key.
      addHexkey(`${label}:hexkey(64-byte)`, h);
      // Still try as raw key (some builds accept 64-byte raw keys).
      addRawKeyHex(`${label}:64-byte`, h);
    }
  };

  const envKey = process.env.RAYBRIDGE_RAYCAST_DB_KEY;
  if (envKey && envKey.trim().length > 0) {
    const v = envKey.trim();
    // Allow passing a raw key expression for manual testing, e.g.:
    //   RAYBRIDGE_RAYCAST_DB_KEY=x'<64 hex chars>'
    //   RAYBRIDGE_RAYCAST_DB_KEY="x'<64 hex chars>'"
    if (/^x'[0-9a-fA-F]+'$/.test(v)) {
      add("env:RAYBRIDGE_RAYCAST_DB_KEY:raw-blob-literal", "key", v);
      add("env:RAYBRIDGE_RAYCAST_DB_KEY:raw-string-x", "key", `"${v}"`);
    } else if (/^\"x'[0-9a-fA-F]+'\"$/.test(v)) {
      add("env:RAYBRIDGE_RAYCAST_DB_KEY:raw-string-x", "key", v);
    } else if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) {
      // Hex-like env key: try as passphrase and as raw key material.
      addKey("env:RAYBRIDGE_RAYCAST_DB_KEY:hex(passphrase)", v);
      addFromHex("env:RAYBRIDGE_RAYCAST_DB_KEY:hex", v);
    } else {
      addKey("env:RAYBRIDGE_RAYCAST_DB_KEY", v);
    }
  }

  // Raycast for Windows writes a key file under %LOCALAPPDATA%\Raycast\last_key.
  try {
    const lastKeyPath = join(getRaycastDataDir(), "last_key");
    if (existsSync(lastKeyPath)) {
      const lastKeyBytes = readFileSync(lastKeyPath);

      const lastKeyUtf8 = trimNulls(lastKeyBytes.toString("utf8"));
      if (lastKeyUtf8 && isPrintableAscii(lastKeyUtf8)) {
        addKey("last_key:utf8", lastKeyUtf8);
        {
          const h = sha256Hex(lastKeyUtf8 + RAYCAST_SALT);
          addKey("last_key:utf8:sha256(+salt)", h);
          // Also treat SHA256 output as raw key material.
          addFromHex("last_key:utf8:sha256(+salt)", h);
        }

        if (/^[0-9a-fA-F]+$/.test(lastKeyUtf8) && lastKeyUtf8.length % 2 === 0) {
          addFromHex("last_key:utf8-hex", lastKeyUtf8);
        }
      }

      addFromHex("last_key:bytes", lastKeyBytes.toString("hex"));
      addKey(
        "last_key:bytes:sha256(bytes+salt)",
        sha256HexBytes(lastKeyBytes, Buffer.from(RAYCAST_SALT, "utf8"))
      );
      addKey("last_key:bytes:sha256(bytes)", sha256HexBytes(lastKeyBytes));
      addKey(
        "last_key:bytes:sha256(salt+bytes)",
        sha256HexBytes(Buffer.from(RAYCAST_SALT, "utf8"), lastKeyBytes)
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
      if (lastKeyBytes.length >= 64) {
        addFromHex(
          "last_key:bytes:last32",
          lastKeyBytes.subarray(32, 64).toString("hex")
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
  for (const target of getWindowsCredentialTargets()) {
    const blob = readWindowsCredentialBlob(target);
    if (!blob) continue;

    addFromHex(`cred:${target}:bytes`, blob.toString("hex"));
    addKey(
      `cred:${target}:bytes:sha256(bytes+salt)`,
      sha256HexBytes(blob, Buffer.from(RAYCAST_SALT, "utf8"))
    );
    addKey(`cred:${target}:bytes:sha256(bytes)`, sha256HexBytes(blob));
    addKey(
      `cred:${target}:bytes:sha256(salt+bytes)`,
      sha256HexBytes(Buffer.from(RAYCAST_SALT, "utf8"), blob)
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
      {
        const h = sha256Hex(utf8 + RAYCAST_SALT);
        addKey(`cred:${target}:utf8:sha256(+salt)`, h);
        addFromHex(`cred:${target}:utf8:sha256(+salt)`, h);
      }
      {
        const h = sha256Hex(RAYCAST_SALT + utf8);
        addKey(`cred:${target}:utf8:sha256(salt+)`, h);
        addFromHex(`cred:${target}:utf8:sha256(salt+)`, h);
      }
      {
        const h = sha256Hex(utf8);
        addKey(`cred:${target}:utf8:sha256(utf8)`, h);
        addFromHex(`cred:${target}:utf8:sha256(utf8)`, h);
      }
      if (/^[0-9a-fA-F]+$/.test(utf8) && utf8.length % 2 === 0) {
        addFromHex(`cred:${target}:utf8-hex`, utf8);
      }

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
      addKey(
        `cred:${target}:utf16le:sha256(salt+)`,
        sha256Hex(RAYCAST_SALT + utf16)
      );
      addKey(`cred:${target}:utf16le:sha256(utf16)`, sha256Hex(utf16));
    }

    const b64 = blob.toString("base64");
    if (b64) {
      addKey(`cred:${target}:bytes:base64`, b64);
      addKey(
        `cred:${target}:bytes:base64:sha256(+salt)`,
        sha256Hex(b64 + RAYCAST_SALT)
      );
      addKey(
        `cred:${target}:bytes:base64:sha256(salt+)`,
        sha256Hex(RAYCAST_SALT + b64)
      );
      addKey(`cred:${target}:bytes:base64:sha256(b64)`, sha256Hex(b64));
    }
  }

  // De-dup while preserving order.
  const seen = new Set<string>();
  const deduped = candidates.filter((c) => {
    const k = `${c.keyPragma}:${c.keyExpr}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  // On Windows, try credential/last_key as passphrase and raw key first (SQLCipher 4 / Microsoft.Data.Sqlite).
  if (process.platform === "win32") {
    const isPriority = (c: KeyCandidate) =>
      (c.label.includes("first32") ||
        c.label.includes("first48") ||
        c.label.includes("last32") ||
        c.label.includes("utf8-hex") ||
        (c.label.startsWith("cred:") && (c.label.includes(":utf8") || c.label.includes(":bytes:base64")))) &&
      (c.label.includes("raw") ||
        c.label.includes("hexkey") ||
        c.label.includes(":utf8") ||
        c.label.includes(":bytes:base64"));
    return [...deduped.filter(isPriority), ...deduped.filter((c) => !isPriority(c))];
  }
  return deduped;
}

function getKeyCandidates(): KeyCandidate[] {
  if (process.platform === "win32") return getWindowsKeyCandidates();
  return getMacKeyCandidates();
}

export interface WindowsKeySourceDiagnostic {
  lastKeyPath: string;
  lastKeyExists: boolean;
  lastKeySize?: number;
  lastKeyPeekHex?: string;
  credentials: { target: string; found: boolean; blobSize?: number }[];
}

/**
 * On Windows, report what key sources exist (last_key file and Credential Manager)
 * without attempting to open the DB. Use for debugging when probe fails.
 */
export function diagnoseWindowsKeySources(): WindowsKeySourceDiagnostic {
  const dataDir = getRaycastDataDir();
  const lastKeyPath = join(dataDir, "last_key");
  const result: WindowsKeySourceDiagnostic = {
    lastKeyPath,
    lastKeyExists: false,
    credentials: [],
  };

  if (existsSync(lastKeyPath)) {
    result.lastKeyExists = true;
    try {
      const st = statSync(lastKeyPath);
      result.lastKeySize = st.size;
      if (st.size > 0) {
        const buf = readFileSync(lastKeyPath, { flag: "r" });
        result.lastKeyPeekHex = buf.subarray(0, Math.min(16, buf.length)).toString("hex");
      }
    } catch {
      // leave size/peek undefined
    }
  }

  for (const target of getWindowsCredentialTargets()) {
    const blob = readWindowsCredentialBlob(target);
    result.credentials.push({
      target,
      found: !!blob,
      blobSize: blob ? blob.length : undefined,
    });
  }

  return result;
}

function looksLikePrintableAscii(buf: Buffer): boolean {
  if (!buf || buf.length === 0) return false;
  for (const b of buf) {
    // reject NULs; allow basic printable ASCII and common whitespace
    if (b === 0) return false;
    if (b === 9 || b === 10 || b === 13) continue;
    if (b < 32 || b > 126) return false;
  }
  return true;
}

function getWindowsBackendDbKeyString(): string | null {
  // Primary source: Raycast-Production/BackendDBKey (expected UTF-8 string).
  const primaryTargets = [
    "Raycast-Production/BackendDBKey",
    "LegacyGeneric:target=Raycast-Production/BackendDBKey",
  ];

  for (const target of primaryTargets) {
    const blob = readWindowsCredentialBlob(target);
    if (!blob || blob.length === 0) continue;

    const utf8 = trimNulls(blob.toString("utf8")).trim();
    if (utf8 && isPrintableAscii(utf8)) return utf8;

    // Some systems store it UTF-16LE.
    const utf16 = trimNulls(blob.toString("utf16le")).trim();
    if (utf16 && isPrintableAscii(utf16)) return utf16;
  }

  // Fallback: last_key file (may not work for all Raycast builds).
  try {
    const dataDir = getRaycastDataDir();
    const lastKeyPath = join(dataDir, "last_key");
    if (existsSync(lastKeyPath)) {
      const blob = readFileSync(lastKeyPath);
      if (blob && blob.length > 0) {
        const utf8 = trimNulls(blob.toString("utf8")).trim();
        if (utf8 && isPrintableAscii(utf8)) return utf8;

        const utf16 = trimNulls(blob.toString("utf16le")).trim();
        if (utf16 && isPrintableAscii(utf16)) return utf16;
      }
    }
  } catch {
    // ignore
  }

  return null;
}

function getRaycastAppxInstallInfo(): { installLocation: string; version: string } | null {
  const psExe = resolveWindowsPowerShellExe();
  const ps = `
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$pkg = Get-AppxPackage -Name 'Raycast.Raycast' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $pkg) { exit 2 }
if (-not $pkg.InstallLocation) { exit 3 }
Write-Output ('LOC|' + $pkg.InstallLocation)
Write-Output ('VER|' + $pkg.Version.ToString())
`.trim();

  try {
    const out = execFileSync(
      psExe,
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(ps)],
      { encoding: "utf-8" }
    );
    let loc = "";
    let ver = "";
    for (const line of out.split(/\r?\n/)) {
      if (line.startsWith("LOC|")) loc = line.slice("LOC|".length).trim();
      if (line.startsWith("VER|")) ver = line.slice("VER|".length).trim();
    }
    if (!loc || !ver) return null;
    return { installLocation: loc, version: ver };
  } catch {
    return null;
  }
}

function ensureRaycastBackendCopy(): { backendDir: string; nodeExe: string } | null {
  if (process.env.RAYBRIDGE_DISABLE_RAYCAST_BACKEND === "1") return null;

  const info = getRaycastAppxInstallInfo();
  if (!info) return null;

  const localAppData = process.env.LOCALAPPDATA;
  if (!localAppData) return null;

  const cacheBase =
    process.env.RAYBRIDGE_RAYCAST_BACKEND_CACHE_DIR?.trim() ||
    join(localAppData, "raybridge", "raycast-backend");
  const dest = join(cacheBase, info.version);
  const nodeExe = join(dest, "node.exe");
  const binding = join(dest, "data.win32-x64-msvc.node");

  if (existsSync(nodeExe) && existsSync(binding)) {
    return { backendDir: dest, nodeExe };
  }

  // Prevent concurrent copy/corruption.
  const lockPath = join(cacheBase, `${info.version}.copy.lock`);
  const acquireLock = (): (() => void) | null => {
    try {
      mkdirSync(cacheBase, { recursive: true });
    } catch {
      /* ignore */
    }

    const start = Date.now();
    while (Date.now() - start < 30_000) {
      try {
        const fd = openSync(lockPath, "wx");
        try {
          const content = JSON.stringify({ pid: process.pid, at: new Date().toISOString() }) + "\n";
          // Write a small marker to help debug stale locks.
          writeFileSync(fd, content, { encoding: "utf-8" } as any);
        } catch {
          /* ignore */
        } finally {
          try {
            closeSync(fd);
          } catch {
            /* ignore */
          }
        }
        return () => {
          try {
            unlinkSync(lockPath);
          } catch {
            /* ignore */
          }
        };
      } catch {
        // Lock exists. If it looks stale, remove it; otherwise wait a bit.
        try {
          const st = statSync(lockPath);
          if (Date.now() - st.mtimeMs > 2 * 60_000) {
            try {
              unlinkSync(lockPath);
              continue;
            } catch {
              /* ignore */
            }
          }
        } catch {
          /* ignore */
        }
        sleepSync(100);
      }
    }
    return null;
  };

  const release = acquireLock();
  if (!release) return null;

  try {
    // Re-check after lock acquisition; another process may have finished copying.
    if (existsSync(nodeExe) && existsSync(binding)) {
      return { backendDir: dest, nodeExe };
    }

  const psExe = resolveWindowsPowerShellExe();
  const src = join(info.installLocation, "Raycast", "backend");
  const ps = `
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$src = '${src.replace(/'/g, "''")}'
$dest = '${dest.replace(/'/g, "''")}'
if (-not (Test-Path $src)) { throw ('Backend dir not found: ' + $src) }
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Path (Join-Path $src '*') -Destination $dest -Recurse -Force
`.trim();

  try {
    execFileSync(psExe, ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(ps)], {
      encoding: "utf-8",
      stdio: "ignore",
    });
  } catch {
    return null;
  }

  if (existsSync(nodeExe) && existsSync(binding)) {
    // Best-effort prune: keep the newest N cached versions (including the active one).
    const keepN = Math.max(1, Number(process.env.RAYBRIDGE_RAYCAST_BACKEND_CACHE_KEEP || "2"));
    try {
      const entries = readdirSync(cacheBase, { withFileTypes: true } as any)
        .filter((d: any) => d?.isDirectory?.())
        .map((d: any) => d.name)
        .filter((name: string) => name !== info.version);

      const versions = entries
        .map((name: string) => {
          const p = join(cacheBase, name);
          let m = 0;
          try {
            m = statSync(p).mtimeMs;
          } catch {
            m = 0;
          }
          return { name, p, m };
        })
        .sort((a, b) => b.m - a.m);

      // Keep N-1 other versions besides the current version.
      for (const v of versions.slice(Math.max(0, keepN - 1))) {
        try {
          rmSync(v.p, { recursive: true, force: true } as any);
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* ignore */
    }
    return { backendDir: dest, nodeExe };
  }

  return null;
  } finally {
    release();
  }
}

async function loadRaycastDataViaWindowsBackend(): Promise<{
  tokens: Map<string, TokenSet[]>;
  prefs: Record<string, Record<string, unknown>>;
} | null> {
  // Small TTL so loadServerContext() can call tokens+prefs without doing two dumps.
  const now = Date.now();
  if (cachedWindowsDataDump && now - cachedWindowsDataDump.atMs < 2000) {
    return {
      tokens: cachedWindowsDataDump.tokens,
      prefs: cachedWindowsDataDump.prefs,
    };
  }

  const key = getWindowsBackendDbKeyString();
  if (!key) {
    if (!warnedWindowsBackendKeyMissing) {
      warnedWindowsBackendKeyMissing = true;
      console.error(
        "raybridge: Windows BackendDBKey not found. Open Raycast once and sign in; then re-run."
      );
    }
    return null;
  }

  const backend = ensureRaycastBackendCopy();
  if (!backend) return null;

  const dataDir = getRaycastDataDir();
  const here = dirname(fileURLToPath(import.meta.url));
  const dumpScript = join(here, "..", "scripts", "raycast_data_dump.cjs");
  if (!existsSync(dumpScript)) {
    console.error("raybridge: Missing scripts/raycast_data_dump.cjs; cannot use Windows backend dump.");
    return null;
  }

  const res = spawnSync(backend.nodeExe, [dumpScript], {
    cwd: backend.backendDir,
    env: {
      ...process.env,
      RAYCAST_DIR: dataDir,
      RAYCAST_BACKEND_DB_KEY: key,
    },
    encoding: "utf-8",
    maxBuffer: 50 * 1024 * 1024,
  });

  if (res.status !== 0) {
    const err = (res.stderr || res.stdout || "").trim();
    if (err) console.error("raybridge: Raycast backend dump failed:", err);
    return null;
  }

  const stdout = (res.stdout || "").trim();
  if (!stdout) return null;

  let parsed: any;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    console.error("raybridge: Raycast backend dump returned non-JSON output");
    return null;
  }

  const tokens = new Map<string, TokenSet[]>();
  const prefs: Record<string, Record<string, unknown>> = {};

  if (parsed && typeof parsed === "object") {
    if (parsed.tokens && typeof parsed.tokens === "object") {
      for (const [k, v] of Object.entries(parsed.tokens)) {
        if (!k) continue;
        if (Array.isArray(v)) tokens.set(k, v as TokenSet[]);
      }
    }
    if (parsed.prefs && typeof parsed.prefs === "object") {
      for (const [k, v] of Object.entries(parsed.prefs)) {
        if (!k) continue;
        if (v && typeof v === "object" && !Array.isArray(v)) prefs[k] = v as Record<string, unknown>;
      }
    }
  }

  cachedWindowsDataDump = { atMs: now, tokens, prefs };
  return { tokens, prefs };
}

function getInitCandidates(): InitCandidate[] {
  const out: InitCandidate[] = [];
  const add = (label: string, initSql: string) => out.push({ label, initSql });

  const addWal = (label: string, initSql: string) =>
    add(`${label}:legacywal`, `PRAGMA mc_legacy_wal = 1;\n${initSql}`);

  // Default cipher scheme (SQLite3MultipleCiphers default is sqleet:ChaCha20).
  add("default", "");
  addWal("default", "");

  // sqleet (ChaCha20) explicit.
  const chacha20 = "PRAGMA cipher = 'chacha20';\n";
  add("chacha20", chacha20);
  addWal("chacha20", chacha20);
  add("chacha20:legacy1", `${chacha20}PRAGMA legacy = 1;\n`);
  addWal("chacha20:legacy1", `${chacha20}PRAGMA legacy = 1;\n`);

  // SQLCipher scheme (try compatibility/legacy modes).
  // SQLCipher 4 default: kdf_iter = 256000; Microsoft.Data.Sqlite with Password= uses this.
  const sqlcipher = "PRAGMA cipher = 'sqlcipher';\n";
  const sqlcipher4Kdf = `${sqlcipher}PRAGMA legacy = 4;\nPRAGMA kdf_iter = 256000;\n`;
  add("sqlcipher:legacy4:kdf256k", sqlcipher4Kdf);
  addWal("sqlcipher:legacy4:kdf256k", sqlcipher4Kdf);
  const sqlcipherLegacies: Array<[string, string]> = [
    ["sqlcipher", sqlcipher],
    ["sqlcipher:legacy4", `${sqlcipher}PRAGMA legacy = 4;\n`],
    ["sqlcipher:legacy3", `${sqlcipher}PRAGMA legacy = 3;\n`],
    ["sqlcipher:legacy2", `${sqlcipher}PRAGMA legacy = 2;\n`],
    ["sqlcipher:legacy1", `${sqlcipher}PRAGMA legacy = 1;\n`],
  ];
  for (const [label, initSql] of sqlcipherLegacies) {
    add(label, initSql);
    addWal(label, initSql);
  }

  // wxSQLite3 cipher schemes.
  const aes256cbc = "PRAGMA cipher = 'aes256cbc';\n";
  add("aes256cbc", aes256cbc);
  addWal("aes256cbc", aes256cbc);
  add("aes256cbc:legacy1", `${aes256cbc}PRAGMA legacy = 1;\n`);
  addWal("aes256cbc:legacy1", `${aes256cbc}PRAGMA legacy = 1;\n`);

  const aes128cbc = "PRAGMA cipher = 'aes128cbc';\n";
  add("aes128cbc", aes128cbc);
  addWal("aes128cbc", aes128cbc);
  add("aes128cbc:legacy1", `${aes128cbc}PRAGMA legacy = 1;\n`);
  addWal("aes128cbc:legacy1", `${aes128cbc}PRAGMA legacy = 1;\n`);

  // System.Data.SQLite RC4 cipher scheme.
  const rc4 = "PRAGMA cipher = 'rc4';\n";
  add("rc4", rc4);
  addWal("rc4", rc4);

  // De-dup while preserving order.
  const seen = new Set<string>();
  const deduped = out.filter((c) => {
    if (seen.has(c.initSql)) return false;
    seen.add(c.initSql);
    return true;
  });

  // On Windows, prioritize SQLCipher paths first (Raycast e_sqlite3.dll exports sqlite3_key),
  // then fall back to other cipher schemes.
  if (process.platform === "win32") {
    const rank = (label: string): number => {
      if (label.startsWith("sqlcipher:legacy4:kdf256k")) return 0;
      if (label.startsWith("sqlcipher")) return 1;
      if (label.startsWith("default")) return 2;
      if (label.startsWith("chacha20")) return 3;
      if (label.startsWith("aes")) return 4;
      if (label.startsWith("rc4")) return 5;
      return 9;
    };

    return deduped
      .map((c, i) => ({ c, i }))
      .sort((a, b) => rank(a.c.label) - rank(b.c.label) || a.i - b.i)
      .map((x) => x.c);
  }
  return deduped;
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

/** Best-effort check: does AES-256-CBC decryption yield the SQLite header? */
function decryptFirstBlockMatchesSqliteHeader(ciphertext: Buffer, key32: Buffer): boolean {
  if (key32.length < 32 || ciphertext.length < AES_BLOCK) return false;

  const check = (plain: Buffer): boolean =>
    plain.length >= SQLITE_HEADER.length && plain.subarray(0, SQLITE_HEADER.length).equals(SQLITE_HEADER);

  try {
    // Layout A: ciphertext is the whole file, IV is all-zero.
    {
      const decipher = createDecipheriv("aes-256-cbc", key32.subarray(0, 32), Buffer.alloc(AES_BLOCK, 0));
      const plain = Buffer.concat([decipher.update(ciphertext.subarray(0, AES_BLOCK)), decipher.final()]);
      if (check(plain)) return true;
    }

    // Layout B: first 16 bytes are IV, ciphertext follows.
    if (ciphertext.length > AES_BLOCK) {
      const iv = ciphertext.subarray(0, AES_BLOCK);
      const ct = ciphertext.subarray(AES_BLOCK);
      if (ct.length >= AES_BLOCK) {
        const decipher = createDecipheriv("aes-256-cbc", key32.subarray(0, 32), iv);
        const plain = Buffer.concat([decipher.update(ct.subarray(0, AES_BLOCK)), decipher.final()]);
        if (check(plain)) return true;
      }
    }
  } catch {
    // ignore
  }

  return false;
}

/** Decrypt full file with AES-256-CBC. Tries common IV layouts and returns plaintext when it looks like SQLite. */
function decryptFileAes256Cbc(ciphertext: Buffer, key32: Buffer): Buffer | null {
  if (key32.length < 32) return null;

  const check = (plain: Buffer): boolean =>
    plain.length >= SQLITE_HEADER.length && plain.subarray(0, SQLITE_HEADER.length).equals(SQLITE_HEADER);

  // Layout A: whole file ciphertext, IV is zero.
  if (ciphertext.length % AES_BLOCK === 0) {
    try {
      const decipher = createDecipheriv("aes-256-cbc", key32.subarray(0, 32), Buffer.alloc(AES_BLOCK, 0));
      const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      if (check(plain)) return plain;
    } catch {
      // ignore
    }
  }

  // Layout B: first 16 bytes IV, ciphertext follows.
  if (ciphertext.length > AES_BLOCK) {
    const iv = ciphertext.subarray(0, AES_BLOCK);
    const ct = ciphertext.subarray(AES_BLOCK);
    if (ct.length % AES_BLOCK === 0) {
      try {
        const decipher = createDecipheriv("aes-256-cbc", key32.subarray(0, 32), iv);
        const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
        if (check(plain)) return plain;
      } catch {
        // ignore
      }
    }
  }

  return null;
}

function decryptFileAes256Gcm(ciphertext: Buffer, key32: Buffer, nonceLen: number): Buffer | null {
  if (key32.length < 32) return null;
  if (ciphertext.length < nonceLen + GCM_TAG + 16) return null;
  try {
    const nonce = ciphertext.subarray(0, nonceLen);
    const tag = ciphertext.subarray(ciphertext.length - GCM_TAG);
    const ct = ciphertext.subarray(nonceLen, ciphertext.length - GCM_TAG);
    const decipher = createDecipheriv("aes-256-gcm", key32.subarray(0, 32), nonce);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    if (plain.subarray(0, SQLITE_HEADER.length).compare(SQLITE_HEADER) === 0) return plain;
    return null;
  } catch {
    return null;
  }
}

function decryptFileChaCha20Poly1305(ciphertext: Buffer, key32: Buffer, nonceLen: number): Buffer | null {
  if (key32.length < 32) return null;
  if (ciphertext.length < nonceLen + GCM_TAG + 16) return null;
  try {
    const nonce = ciphertext.subarray(0, nonceLen);
    const tag = ciphertext.subarray(ciphertext.length - GCM_TAG);
    const ct = ciphertext.subarray(nonceLen, ciphertext.length - GCM_TAG);
    const decipher = createDecipheriv("chacha20-poly1305", key32.subarray(0, 32), nonce, {
      authTagLength: GCM_TAG,
    } as any);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    if (plain.subarray(0, SQLITE_HEADER.length).compare(SQLITE_HEADER) === 0) return plain;
    return null;
  } catch {
    return null;
  }
}

/**
 * If Raycast uses file-level AES encryption (decrypt then open with vanilla SQLite), try to find
 * the key and open. Returns a config with transparentDecryptKey if successful.
 */
function tryTransparentDecryptOpen(
  sqlcipherPath: string,
  dataDir: string
): SqlcipherOpenConfig | null {
  if (process.platform !== "win32") return null;
  const dbs = listRaycastDbFiles(dataDir).filter((p) => existsSync(p));
  const dbPath = dbs.find((p) => basename(p) === "main.db") ?? dbs[0];
  if (!dbPath) return null;
  let ciphertext: Buffer;
  try {
    ciphertext = readFileSync(dbPath);
  } catch {
    return null;
  }
  if (ciphertext.length < 16) return null;

  const keysToTry: { key: Buffer; label: string }[] = [];
  const lastKeyPath = join(dataDir, "last_key");
  if (existsSync(lastKeyPath)) {
    const lastKeyBytes = readFileSync(lastKeyPath);
    if (lastKeyBytes.length >= 32) {
      keysToTry.push({ key: lastKeyBytes.subarray(0, 32), label: "last_key:first32" });
      if (lastKeyBytes.length >= 64) {
        keysToTry.push({ key: lastKeyBytes.subarray(32, 64), label: "last_key:last32" });
      }
    }
  }
  for (const target of getWindowsCredentialTargets()) {
    const blob = readWindowsCredentialBlob(target);
    if (blob && blob.length >= 32) {
      keysToTry.push({ key: blob.subarray(0, 32), label: `cred:${target}:first32` });
    }
  }

  for (const { key } of keysToTry) {
    // Quick header sniff (CBC layouts) to reduce work.
    if (!decryptFirstBlockMatchesSqliteHeader(ciphertext, key)) {
      // GCM/ChaCha20-Poly1305 won't match the CBC sniff; still try full decrypt below.
    }

    const plain =
      decryptFileAes256Cbc(ciphertext, key) ??
      decryptFileAes256Gcm(ciphertext, key, 12) ??
      decryptFileAes256Gcm(ciphertext, key, 16) ??
      decryptFileChaCha20Poly1305(ciphertext, key, 12);
    if (!plain || plain.subarray(0, 16).compare(SQLITE_HEADER) !== 0) continue;
    const tmpDir = mkdtempSync(join(tmpdir(), "raybridge-decrypt-"));
    const tmpDb = join(tmpDir, basename(dbPath));
    try {
      writeFileSync(tmpDb, plain);
      const input = ".mode json\nSELECT count(*) AS c FROM sqlite_master;";
      const proc = spawnSync(sqlcipherPath, [tmpDb], {
        input,
        encoding: "utf-8",
        maxBuffer: 1024 * 1024,
        timeout: 3000,
      });
      try {
        for (const ext of ["", "-wal", "-shm"]) unlinkSync(tmpDb + ext);
        rmdirSync(tmpDir);
      } catch {
        /* ignore */
      }
      if (proc.status === 0 && proc.stdout && /\[\s*\{/.test(proc.stdout)) {
        return {
          initSql: "",
          keyPragma: "key",
          keyExpr: "''",
          transparentDecryptKey: key,
        };
      }
    } catch {
      try {
        for (const ext of ["", "-wal", "-shm"]) unlinkSync(tmpDb + ext);
        rmdirSync(tmpDir);
      } catch {
        /* ignore */
      }
    }
  }
  return null;
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

  // Transparent file-level decryption (AES-256-CBC): decrypt then open with no key.
  if (openConfig.transparentDecryptKey) {
    try {
      const ciphertext = readFileSync(dbPath);
      if (ciphertext.length >= 16 && ciphertext.length % AES_BLOCK === 0) {
        const plain = decryptFileAes256Cbc(ciphertext, openConfig.transparentDecryptKey);
        if (plain && plain.subarray(0, 16).compare(SQLITE_HEADER) === 0) {
          writeFileSync(tmpDb, plain);
          const input = ".mode json\n" + sql;
          const proc = spawnSync(sqlcipherPath, [tmpDb], {
            input,
            encoding: "utf-8",
            maxBuffer: 10 * 1024 * 1024,
            timeout: 5000,
          });
          cleanup();
          if (proc.status === 0 && proc.stdout) {
            const jsonStr = stripShellPreamble(String(proc.stdout));
            try {
              return JSON.parse(jsonStr.trim());
            } catch {
              return [];
            }
          }
        }
      }
    } catch {
      /* fall through */
    }
    cleanup();
    return [];
  }

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
        timeout: 1500,
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

const PROBE_CONCURRENCY = 8;
// Keep probes reasonably fast; wrong-key attempts tend to fail quickly.
const PROBE_TIMEOUT_MS = 800;

function runSqlcipherQueryAsync(
  sqlcipherPath: string,
  dbPath: string,
  openConfig: SqlcipherOpenConfig,
  sql: string
): Promise<any[]> {
  const stripShellPreamble = (out: string): string => {
    let s = out ?? "";
    s = s.replace(/^(?:\s*ok\s*\r?\n)+/i, "").trimStart();
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
        /* ignore */
      }
    }
    try {
      rmdirSync(tmpDir);
    } catch {
      /* ignore */
    }
  };

  if (openConfig.transparentDecryptKey) {
    try {
      const ciphertext = readFileSync(dbPath);
      if (ciphertext.length >= 16 && ciphertext.length % AES_BLOCK === 0) {
        const plain = decryptFileAes256Cbc(ciphertext, openConfig.transparentDecryptKey);
        if (plain && plain.subarray(0, 16).compare(SQLITE_HEADER) === 0) {
          writeFileSync(tmpDb, plain);
          const input = ".mode json\n" + sql;
          return new Promise((resolve, reject) => {
            const child = spawn(sqlcipherPath, [tmpDb], {
              stdio: ["pipe", "pipe", "pipe"],
              windowsHide: true,
            });
            let stdout = "";
            const to = setTimeout(() => {
              try {
                child.kill();
              } catch {
                /* ignore */
              }
              cleanup();
              reject(new Error("Probe timeout"));
            }, PROBE_TIMEOUT_MS);
            child.stdout?.setEncoding("utf-8").on("data", (chunk) => {
              stdout += chunk;
            });
            child.on("error", (err) => {
              clearTimeout(to);
              cleanup();
              reject(err);
            });
            child.on("close", (code, signal) => {
              clearTimeout(to);
              cleanup();
              if (signal) reject(new Error(`sqlcipher signal ${signal}`));
              else if (typeof code === "number" && code !== 0) reject(new Error(`sqlcipher exited ${code}`));
              else {
                try {
                  const jsonStr = stripShellPreamble(stdout);
                  resolve(JSON.parse(jsonStr.trim()));
                } catch {
                  resolve([]);
                }
              }
            });
            child.stdin?.end(input, "utf-8");
          });
        }
      }
    } catch {
      /* fall through */
    }
    cleanup();
    return Promise.resolve([]);
  }

  let targetDb = tmpDb;
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

  return new Promise((resolve, reject) => {
    const child = spawn(sqlcipherPath, [targetDb], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const to = setTimeout(() => {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
      cleanup();
      reject(new Error("Probe timeout"));
    }, PROBE_TIMEOUT_MS);

    child.stdout?.setEncoding("utf-8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr?.setEncoding("utf-8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (err) => {
      clearTimeout(to);
      cleanup();
      reject(err);
    });
    child.on("close", (code, signal) => {
      clearTimeout(to);
      cleanup();
      if (signal) {
        reject(new Error(`sqlcipher signal ${signal}`));
        return;
      }
      if (typeof code === "number" && code !== 0) {
        const err: any = new Error(`sqlcipher exited ${code}`);
        err.stderr = stderr;
        err.stdout = stdout;
        reject(err);
        return;
      }
      try {
        const jsonStr = stripShellPreamble(stdout);
        resolve(JSON.parse(jsonStr.trim()));
      } catch {
        resolve([]);
      }
    });
    child.stdin?.end(input, "utf-8");
  });
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

  // On Windows, try file-level AES-256-CBC decryption first (Raycast may encrypt the file then use vanilla SQLite).
  const transparent = tryTransparentDecryptOpen(sqlcipherPath, dataDir);
  if (transparent) {
    cachedOpenConfig = transparent;
    return cachedOpenConfig;
  }

  const keyCandidates = getKeyCandidates();
  if (keyCandidates.length === 0) {
    throw new Error("No Raycast DB key candidates found");
  }

  const initCandidates = getInitCandidates();
  // Probe only the first DB to speed up (same key/cipher works for all).
  const probeDbs = dbs.slice(0, 1);

  const debug = process.env.RAYBRIDGE_DEBUG_DB_OPEN === "1";
  const scratchPath = join(process.cwd(), "raybridge-probe.log");
  const debugLog = (msg: string) => {
    if (!debug) return;
    try {
      appendFileSync(scratchPath, msg + "\n");
    } catch {
      /* ignore */
    }
  };
  if (debug) {
    try {
      writeFileSync(
        scratchPath,
        `raybridge DB probe ${new Date().toISOString()}\n` +
          `dbs=${probeDbs.map((p) => basename(p)).join(", ")}\n` +
          `init candidates=${initCandidates.length}, key candidates=${keyCandidates.length}\n` +
          `max attempts=${initCandidates.length * keyCandidates.length * probeDbs.length}\n\n`
      );
    } catch {
      /* ignore */
    }
    console.log(`raybridge: probe log → ${scratchPath}`);
  }

  const errorCounts = new Map<string, number>();
  const incErr = (k: string) => errorCounts.set(k, (errorCounts.get(k) || 0) + 1);

  const probe = async (initSubset: InitCandidate[], keySubset: KeyCandidate[], stageLabel: string) => {
    const tasks: { init: InitCandidate; key: KeyCandidate; db: string }[] = [];
    for (const init of initSubset) {
      for (const key of keySubset) {
        for (const db of probeDbs) tasks.push({ init, key, db });
      }
    }

    const totalAttempts = tasks.length;
    let nextIdx = 0;
    let winner: SqlcipherOpenConfig | null = null;
    let attemptsDone = 0;

    if (debug) {
      debugLog(`STAGE: ${stageLabel} (init=${initSubset.length}, keys=${keySubset.length}, attempts=${totalAttempts})`);
    }

    async function runOne(): Promise<void> {
      const idx = nextIdx++;
      if (idx >= tasks.length || winner) return;
      const { init, key, db } = tasks[idx];
      attemptsDone++;
      if (debug && attemptsDone % 500 === 0) {
        debugLog(`  progress ${attemptsDone}/${totalAttempts}`);
      }
      try {
        const probeRows = await runSqlcipherQueryAsync(
          sqlcipherPath,
          db,
          { initSql: init.initSql, keyPragma: key.keyPragma, keyExpr: key.keyExpr },
          "SELECT count(*) AS c FROM sqlite_master;"
        );
        if (Array.isArray(probeRows) && probeRows.length > 0) {
          winner = { initSql: init.initSql, keyPragma: key.keyPragma, keyExpr: key.keyExpr };
          if (debug) {
            debugLog(`OPEN OK: init=${init.label}, key=${key.label}, db=${basename(db)}`);
            console.log(`raybridge: open OK → ${scratchPath}`);
          }
          return;
        }
        incErr("probe_empty");
      } catch (err: any) {
        const msg = [err?.message, err?.stderr, err?.stdout]
          .filter(Boolean)
          .join("\n")
          .toLowerCase();
        if (msg.includes("file is not a database")) incErr("not_a_database");
        else if (msg.includes("database is locked")) incErr("locked");
        else if (msg.includes("etimedout") || msg.includes("timed out") || msg.includes("probe timeout")) incErr("timeout");
        else if (msg.includes("syntax error")) incErr("syntax");
        else if (msg.includes("malformed")) incErr("malformed");
        else incErr("other");
      }
      if (!winner) await runOne();
    }

    await Promise.all(Array.from({ length: PROBE_CONCURRENCY }, () => runOne()));
    return winner;
  };

  const fullProbe = process.env.RAYBRIDGE_DB_PROBE_FULL === "1";
  const wideProbe = fullProbe || process.env.RAYBRIDGE_DB_PROBE_WIDE === "1";
  const KEY_FAST_LIMIT = Number(process.env.RAYBRIDGE_DB_PROBE_FAST_KEYS || "20");
  const INIT_FAST_LIMIT = Number(process.env.RAYBRIDGE_DB_PROBE_FAST_INITS || "2");

  const initFast = initCandidates.slice(0, Math.max(1, INIT_FAST_LIMIT));
  const keysFast = keyCandidates.slice(0, Math.max(1, KEY_FAST_LIMIT));

  let winner: SqlcipherOpenConfig | null = null;
  winner = await probe(initFast, keysFast, "fast inits + fast keys");
  if (!winner) winner = await probe(initFast, keyCandidates, "fast inits + all keys");
  if (!winner && wideProbe) winner = await probe(initCandidates, keysFast, "all inits + fast keys");
  if (!winner && fullProbe) winner = await probe(initCandidates, keyCandidates, "FULL");

  if (winner) {
    cachedOpenConfig = winner;
    return cachedOpenConfig;
  }

  if (debug) {
    const top = Array.from(errorCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);
    debugLog(`FAILED: ${top.map(([k, v]) => `${k}=${v}`).join(", ")}`);
    console.log(`raybridge: probe failed → ${scratchPath}`);
  }

  const hint = fullProbe
    ? ""
    : " (set RAYBRIDGE_DB_PROBE_FULL=1 to run a full scan; it can take several minutes)";
  throw new Error("Could not open Raycast DB with any known key candidate" + hint);
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
    // On Windows, prefer Raycast's own backend DB layer (works even when SQLCipher probing fails).
    if (process.platform === "win32") {
      const dumped = await loadRaycastDataViaWindowsBackend();
      if (dumped && dumped.tokens.size > 0) return dumped.tokens;
    }

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
    if (process.platform === "win32") {
      const dumped = await loadRaycastDataViaWindowsBackend();
      if (dumped && Object.keys(dumped.prefs).length > 0) return dumped.prefs;
    }

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
