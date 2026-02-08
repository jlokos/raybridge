import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
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
import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import { getRaycastDataDir } from "./raycast-paths.js";
import { resolveWindowsPowerShellExe } from "./windows-exe.js";
import { normalizeBackendDump, normalizeExtensionsRows } from "./auth-normalize.js";

const RAYCAST_SALT = "yvkwWXzxPPBAqY2tmaKrB*DvYjjMaeEf";

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

export interface RaycastAuthData {
  tokens: Map<string, TokenSet[]>;
  prefs: Record<string, Record<string, unknown>>;
}

const emptyAuthData = (): RaycastAuthData => ({ tokens: new Map(), prefs: {} });

// ============================================================================
// Public API
// ============================================================================

export async function loadRaycastAuthData(): Promise<RaycastAuthData> {
  if (process.platform === "win32") {
    try {
      const data = await loadRaycastAuthDataWindowsBackend();
      return data ?? emptyAuthData();
    } catch (err: any) {
      console.error(`raybridge: Windows OAuth load failed: ${err?.message || String(err)}`);
      return emptyAuthData();
    }
  }

  if (process.platform === "darwin") {
    try {
      return loadRaycastAuthDataMacSqlcipher();
    } catch (err: any) {
      console.error(`raybridge: Could not read Raycast auth data: ${err?.message || String(err)}`);
      return emptyAuthData();
    }
  }

  return emptyAuthData();
}

// ============================================================================
// macOS: sqlcipher (minimal, single query)
// ============================================================================

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function getMacDatabasePassphrase(): string {
  const keyHex = execFileSync(
    "security",
    ["find-generic-password", "-s", "Raycast", "-a", "database_key", "-w"],
    { encoding: "utf-8" }
  ).trim();
  return sha256Hex(keyHex + RAYCAST_SALT);
}

function sleepSync(ms: number) {
  if (typeof Bun !== "undefined" && (Bun as any).sleepSync) {
    (Bun as any).sleepSync(ms);
    return;
  }
  const start = Date.now();
  while (Date.now() - start < ms) {
    // Busy wait fallback
  }
}

function stripShellPreamble(out: string): string {
  let s = out ?? "";
  // Some shells print leading "ok" lines for PRAGMAs.
  s = s.replace(/^(?:\s*ok\s*\r?\n)+/i, "");
  s = s.trimStart();

  // If there is any other preamble, try to locate the beginning of JSON.
  if (s.length > 0 && s[0] !== "[" && s[0] !== "{") {
    const idx = s.search(/[\[{]/);
    if (idx >= 0) s = s.slice(idx);
  }

  return s.trim();
}

function loadRaycastAuthDataMacSqlcipher(): RaycastAuthData {
  const dataDir = getRaycastDataDir();
  const dbPath = join(dataDir, "raycast-enc.sqlite");
  if (!existsSync(dbPath)) return emptyAuthData();

  const passphrase = getMacDatabasePassphrase();
  const sqlcipherExe = process.env.RAYBRIDGE_SQLCIPHER_PATH?.trim() || "sqlcipher";

  const sql =
    "SELECT name, tokenSets, preferences FROM extensions " +
    "WHERE (tokenSets IS NOT NULL AND tokenSets != '') " +
    "OR (preferences IS NOT NULL AND preferences != '');";

  const retries = 3;
  for (let attempt = 1; attempt <= retries; attempt++) {
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

    try {
      copyFileSync(dbPath, tmpDb);
      for (const ext of ["-wal", "-shm"]) {
        const src = dbPath + ext;
        if (existsSync(src)) copyFileSync(src, tmpDb + ext);
      }

      const input = `PRAGMA key = '${passphrase}';\n.mode json\n${sql}\n`;
      const proc = spawnSync(sqlcipherExe, [tmpDb], {
        input,
        encoding: "utf-8",
        maxBuffer: 10 * 1024 * 1024,
      });

      cleanup();

      if (proc.error) throw proc.error;
      if (typeof proc.status === "number" && proc.status !== 0) {
        throw new Error(`sqlcipher exited with code ${proc.status}`);
      }
      if (proc.signal) throw new Error(`sqlcipher exited due to signal ${proc.signal}`);

      const jsonStr = stripShellPreamble(String(proc.stdout || ""));
      const rows = JSON.parse(jsonStr.trim());
      return normalizeExtensionsRows(rows);
    } catch (err: any) {
      cleanup();
      const message = err?.message || String(err);
      const isTransient =
        message.includes("database is locked") ||
        message.includes("database disk image is malformed") ||
        message.includes("no such table");

      if (isTransient && attempt < retries) {
        sleepSync(50 * attempt);
        continue;
      }
      throw err;
    }
  }

  return emptyAuthData();
}

// ============================================================================
// Windows: Raycast backend runtime (no sqlcipher fallback)
// ============================================================================

function encodePowerShell(script: string): string {
  // PowerShell expects UTF-16LE for -EncodedCommand.
  return Buffer.from(script, "utf16le").toString("base64");
}

function trimNulls(value: string): string {
  return value.replace(/\0+$/g, "").trim();
}

function isPrintableAscii(value: string): boolean {
  // Avoid feeding arbitrary binary garbage into any string contexts.
  return /^[\x20-\x7E]+$/.test(value);
}

const WINDOWS_BACKENDDBKEY_TARGETS = [
  "Raycast-Production/BackendDBKey",
  "LegacyGeneric:target=Raycast-Production/BackendDBKey",
] as const;

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

let warnedWindowsBackendKeyMissing = false;

function getWindowsBackendDbKeyString(): string | null {
  for (const target of WINDOWS_BACKENDDBKEY_TARGETS) {
    const blob = readWindowsCredentialBlob(target);
    if (!blob || blob.length === 0) continue;

    const utf8 = trimNulls(blob.toString("utf8")).trim();
    if (utf8 && isPrintableAscii(utf8)) return utf8;

    const utf16 = trimNulls(blob.toString("utf16le")).trim();
    if (utf16 && isPrintableAscii(utf16)) return utf16;
  }

  // Fallback: last_key file (best effort).
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
    while (Date.now() - start < 10_000) {
      try {
        const fd = openSync(lockPath, "wx");
        try {
          const content = JSON.stringify({ pid: process.pid, at: new Date().toISOString() }) + "\n";
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
          if (Date.now() - st.mtimeMs > 60_000) {
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
      return { backendDir: dest, nodeExe };
    }
    return null;
  } finally {
    release();
  }
}

let cachedWindowsAuth: { atMs: number; data: RaycastAuthData } | null = null;

async function loadRaycastAuthDataWindowsBackend(): Promise<RaycastAuthData | null> {
  if (process.platform !== "win32") return null;

  const now = Date.now();
  if (cachedWindowsAuth && now - cachedWindowsAuth.atMs < 2000) {
    return cachedWindowsAuth.data;
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

  const script = `
const fs = require("node:fs");
const path = require("node:path");

const DEBUG = process.env.RAYBRIDGE_DEBUG_WINDOWS_BACKEND === "1";
function dbg(msg) {
  if (!DEBUG) return;
  try { process.stderr.write("[raybridge-backend] " + String(msg) + "\\n"); } catch {}
}

function fail(msg) {
  process.stderr.write(String(msg || "unknown error") + "\\n");
  process.exit(1);
}

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function listDbFiles(dir) {
  try {
    const entries = fs.readdirSync(dir);
    return entries
      .filter((n) => /\\.(db|sqlite|sqlite3)$/i.test(n))
      .map((n) => path.join(dir, n));
  } catch {
    return [];
  }
}

function loadBinding() {
  const bindingPath = path.join(process.cwd(), "data.win32-x64-msvc.node");
  if (!fs.existsSync(bindingPath)) fail("missing backend binding: " + bindingPath);
  let binding;
  try {
    binding = require(bindingPath);
  } catch (err) {
    fail("could not require binding: " + (err && err.message ? err.message : String(err)));
  }
  dbg("binding keys=" + Object.keys(binding || {}).join(","));
  return binding;
}

async function maybeAwait(v) {
  if (v && typeof v.then === "function") return await v;
  return v;
}

function firstRows(res) {
  if (Array.isArray(res)) return res;
  if (res && Array.isArray(res.rows)) return res.rows;
  if (res && Array.isArray(res.result)) return res.result;
  return null;
}

async function tryQuery(target, dbId, sql) {
  if (!target) return null;

  const methods = [
    "query",
    "queryRaw",
    "rawQuery",
    "select",
    "all",
    "execute",
    "run",
  ];

  const variants = [
    [dbId, sql],
    [sql, dbId],
    [{ dbPath: dbId, sql }],
    [{ databasePath: dbId, sql }],
    [{ path: dbId, sql }],
    [{ database: dbId, sql }],
    [{ kind: dbId, sql }],
    [{ dbKind: dbId, sql }],
    [{ databaseKind: dbId, sql }],
    [dbId, sql, []],
  ];

  for (const m of methods) {
    const fn = target[m];
    if (typeof fn !== "function") continue;
    for (const args of variants) {
      try {
        const out = await maybeAwait(fn.apply(target, args));
        const rows = firstRows(out);
        if (rows) return rows;
      } catch (err) {
        dbg(m + " failed: " + (err && err.message ? err.message : String(err)));
      }
    }
  }
  return null;
}

function parsePreferences(prefJson) {
  const parsed = safeJsonParse(prefJson);
  if (!Array.isArray(parsed)) return null;
  const out = {};
  for (const p of parsed) {
    if (!p || typeof p !== "object") continue;
    if (typeof p.name !== "string") continue;
    if (!Object.prototype.hasOwnProperty.call(p, "value")) continue;
    out[p.name] = p.value;
  }
  return out;
}

function parseTokenSets(tokenJson) {
  const parsed = safeJsonParse(tokenJson);
  if (!parsed) return null;
  return Array.isArray(parsed) ? parsed : [parsed];
}

function createDbClient(binding, raycastDir, backendKey) {
  const C = binding && binding.DatabaseClient;
  if (typeof C !== "function") return null;

  if (DEBUG) {
    try {
      dbg("DatabaseClient proto=" + Object.getOwnPropertyNames(C.prototype || {}).join(","));
    } catch {
      // ignore
    }
  }

  const attempts = [
    () => new C({ raycastDir, backendKey }),
    () => new C({ dataDir: raycastDir, backendKey }),
    () => new C({ dataDir: raycastDir, key: backendKey }),
    () => new C(raycastDir, backendKey),
    () => new C(backendKey, raycastDir),
    () => new C(),
  ];

  for (const mk of attempts) {
    try {
      const client = mk();
      if (!client) continue;
      try {
        if (typeof client.setKey === "function") client.setKey(backendKey);
        if (typeof client.key === "function") client.key(backendKey);
      } catch {
        // ignore
      }
      return client;
    } catch (err) {
      dbg("DatabaseClient ctor failed: " + (err && err.message ? err.message : String(err)));
      continue;
    }
  }

  return null;
}

async function main() {
  const raycastDir = process.env.RAYCAST_DIR;
  const backendKey = process.env.RAYCAST_BACKEND_DB_KEY;
  if (!raycastDir) fail("RAYCAST_DIR is required");
  if (!backendKey) fail("RAYCAST_BACKEND_DB_KEY is required");

  dbg("raycastDir=" + raycastDir);
  const dbFiles = listDbFiles(raycastDir);
  dbg("dbFiles=" + dbFiles.map((p) => path.basename(p)).join(","));
  if (dbFiles.length === 0) fail("no DB files found under " + raycastDir);

  const binding = loadBinding();

  const client = createDbClient(binding, raycastDir, backendKey);
  if (!client) fail("could not create DatabaseClient");

  const probeSql =
    "SELECT count(*) AS c FROM sqlite_master WHERE type='table' AND name='extensions';";
  const dataSql =
    "SELECT name, tokenSets, preferences FROM extensions " +
    "WHERE (tokenSets IS NOT NULL AND tokenSets != '') " +
    "OR (preferences IS NOT NULL AND preferences != '');";

  let rows = null;

  // Attempt 1: query by DB file path.
  for (const dbPath of dbFiles) {
    dbg("trying dbPath=" + path.basename(dbPath));
    const probeRows = await tryQuery(client, dbPath, probeSql);
    const ok = probeRows && probeRows[0] && Number(probeRows[0].c) > 0;
    dbg("hasExtensionsTable=" + ok);
    if (!ok) continue;
    rows = await tryQuery(client, dbPath, dataSql);
    if (rows) break;
  }

  // Attempt 2: query by DatabaseKind.
  if (!rows && binding && binding.DatabaseKind && typeof binding.DatabaseKind === "object") {
    const kinds = [];
    try {
      for (const [k, v] of Object.entries(binding.DatabaseKind)) {
        if (/^\\d+$/.test(k)) continue;
        kinds.push([k, v]);
      }
    } catch {
      // ignore
    }

    dbg("DatabaseKind keys=" + kinds.map((kv) => kv[0]).join(","));

    for (const [k, v] of kinds) {
      dbg("trying kind=" + k);
      const probeRows = await tryQuery(client, v, probeSql);
      const ok = probeRows && probeRows[0] && Number(probeRows[0].c) > 0;
      dbg("hasExtensionsTable=" + ok);
      if (!ok) continue;
      rows = await tryQuery(client, v, dataSql);
      if (rows) break;
    }
  }

  if (!rows) fail("could not open any Raycast DB with extensions table");

  const tokens = {};
  const prefs = {};

  for (const row of rows || []) {
    const name = row && row.name;
    if (typeof name !== "string" || !name) continue;

    if (typeof row.tokenSets === "string" && row.tokenSets.trim()) {
      const sets = parseTokenSets(row.tokenSets);
      if (sets && Array.isArray(sets) && sets.length > 0) tokens[name] = sets;
    }
    if (typeof row.preferences === "string" && row.preferences.trim()) {
      const p = parsePreferences(row.preferences);
      if (p && Object.keys(p).length > 0) prefs[name] = p;
    }
  }

  process.stdout.write(JSON.stringify({ tokens, prefs }));
}

main().catch((err) => fail(err && err.message ? err.message : String(err)));
`.trim();

  const res = spawnSync(backend.nodeExe, ["-e", script], {
    cwd: backend.backendDir,
    env: {
      ...process.env,
      RAYCAST_DIR: dataDir,
      RAYCAST_BACKEND_DB_KEY: key,
    },
    encoding: "utf-8",
    maxBuffer: 50 * 1024 * 1024,
  });

  if (res.error) throw res.error;
  if (res.status !== 0) {
    const err = (res.stderr || res.stdout || "").trim();
    throw new Error(err || `raycast backend dump failed (exit ${res.status})`);
  }

  const stdout = (res.stdout || "").trim();
  if (!stdout) return null;

  let parsed: any;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("raycast backend dump returned non-JSON output");
  }

  const data = normalizeBackendDump(parsed);
  cachedWindowsAuth = { atMs: now, data };
  return data;
}
