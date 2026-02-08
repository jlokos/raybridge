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

function firstArray(res) {
  if (Array.isArray(res)) return res;
  if (res && Array.isArray(res.rows)) return res.rows;
  if (res && Array.isArray(res.result)) return res.result;
  if (res && Array.isArray(res.items)) return res.items;
  if (res && Array.isArray(res.data)) return res.data;
  return null;
}

function parsePreferences(value) {
  if (!value) return null;

  if (typeof value === "string") {
    const parsed = safeJsonParse(value);
    if (!parsed) return null;
    value = parsed;
  }

  if (Array.isArray(value)) {
    const out = {};
    for (const p of value) {
      if (!p || typeof p !== "object") continue;
      if (typeof p.name !== "string") continue;
      if (!Object.prototype.hasOwnProperty.call(p, "value")) continue;
      out[p.name] = p.value;
    }
    return Object.keys(out).length > 0 ? out : null;
  }

  if (value && typeof value === "object") {
    return value;
  }

  return null;
}

function parseTokenSets(value) {
  if (!value) return null;

  if (typeof value === "string") {
    const parsed = safeJsonParse(value);
    if (!parsed) return null;
    value = parsed;
  }

  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") return [value];
  return null;
}

function getExtName(row) {
  if (!row || typeof row !== "object") return null;
  const candidates = [
    "name",
    "extensionName",
    "extension_name",
    "extensionId",
    "extension_id",
    "identifier",
    "id",
  ];
  for (const k of candidates) {
    const v = row[k];
    if (typeof v === "string" && v) return v;
  }
  return null;
}

function createDbClient(binding, raycastDir, backendKey) {
  const C = binding && binding.DatabaseClient;
  if (typeof C !== "function") return null;

  if (DEBUG) {
    try {
      dbg("DatabaseClient length=" + String(C.length));
      dbg("DatabaseClient proto=" + Object.getOwnPropertyNames(C.prototype || {}).join(","));
    } catch {
      // ignore
    }
  }

  const noopReport = () => {};
  const attempts = [
    () => new C(raycastDir),
    () => new C(raycastDir, noopReport),
    () => new C(raycastDir, noopReport, backendKey),
    () => new C(raycastDir, backendKey, noopReport),
    () => new C(raycastDir, backendKey),
    () => new C(),
  ];

  for (const mk of attempts) {
    try {
      const client = mk();
      if (!client) continue;
      return client;
    } catch (err) {
      dbg("DatabaseClient ctor failed: " + (err && err.message ? err.message : String(err)));
      continue;
    }
  }

  return null;
}

function getDatabaseCtor(binding) {
  const Database =
    (binding && (binding.Database || binding.default)) ||
    (typeof binding === "function" ? binding : null);
  return typeof Database === "function" ? Database : null;
}

function tryOpenWithDatabase(Database, dbPath, backendKey) {
  let db;
  try {
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
  } catch {
    try {
      db = new Database(dbPath);
    } catch {
      return null;
    }
  }

  // Best-effort: set encryption key if the binding supports it and we have a key.
  if (backendKey) {
    try {
      if (db && typeof db.pragma === "function") {
        const escaped = String(backendKey).replace(/'/g, "''");
        db.pragma("key='" + escaped + "'");
      }
    } catch {
      // ignore
    }
  }

  return db;
}

function hasExtensionsTable(db) {
  try {
    if (!db) return false;
    if (typeof db.prepare === "function") {
      const row = db
        .prepare("SELECT count(*) AS c FROM sqlite_master WHERE type='table' AND name='extensions'")
        .get();
      return !!row && Number(row.c) > 0;
    }
  } catch {
    // ignore
  }
  return false;
}

function queryExtensionsTable(db) {
  if (!db || typeof db.prepare !== "function") return [];
  try {
    return db
      .prepare(
        "SELECT name, tokenSets, preferences FROM extensions WHERE (tokenSets IS NOT NULL AND tokenSets != '') OR (preferences IS NOT NULL AND preferences != '')"
      )
      .all();
  } catch {
    return [];
  }
}

async function callMaybe(obj, name) {
  if (!obj) return null;
  const v = obj[name];
  if (typeof v === "function") return await maybeAwait(v.call(obj));
  return v;
}

function protoKeys(obj) {
  try {
    const proto = Object.getPrototypeOf(obj);
    return Object.getOwnPropertyNames(proto || {}).filter((n) => n !== "constructor");
  } catch {
    return [];
  }
}

function pickRowsFromResult(res) {
  if (!res) return null;
  const arr = firstArray(res);
  if (arr) return arr;
  return null;
}

async function getNodeExtensionsRows(client) {
  const nodeExt = await callMaybe(client, "nodeExtensions");
  if (!nodeExt) return null;

  dbg("nodeExtensions typeof=" + typeof nodeExt + " isArray=" + String(Array.isArray(nodeExt)));
  if (Array.isArray(nodeExt)) return nodeExt;

  // nodeExt is likely a repository object.
  const repo = nodeExt;
  dbg("NodeExtensionsRepository proto=" + protoKeys(repo).join(","));

  const preferred = [
    "getAllExtensions",
    "getInstalledExtensions",
    "getExtensions",
    "getAll",
    "all",
    "listAll",
    "list",
    "entries",
  ];

  for (const m of preferred) {
    const fn = repo && repo[m];
    if (typeof fn !== "function") continue;
    try {
      dbg("trying nodeExtensions." + m + "()");
      const out = await maybeAwait(fn.call(repo));
      const rows = pickRowsFromResult(out);
      if (rows) return rows;
    } catch (err) {
      dbg("nodeExtensions." + m + " failed: " + (err && err.message ? err.message : String(err)));
    }
  }

  // Fallback: try any safe-looking, zero-arg getter/list method.
  const names = protoKeys(repo);
  for (const m of names) {
    if (!m) continue;
    if (!/(get|list|all|fetch|load)/i.test(m)) continue;
    if (/(set|delete|remove|drop|insert|update|write|save|create|reset|shutdown|restore|backup)/i.test(m)) continue;
    const fn = repo[m];
    if (typeof fn !== "function") continue;
    try {
      dbg("trying nodeExtensions." + m + "()");
      const out = await maybeAwait(fn.call(repo));
      const rows = pickRowsFromResult(out);
      if (rows) return rows;
    } catch (err) {
      dbg("nodeExtensions." + m + " failed: " + (err && err.message ? err.message : String(err)));
    }
  }

  return null;
}

async function main() {
  const raycastDir = process.env.RAYCAST_DIR;
  const backendKey = process.env.RAYCAST_BACKEND_DB_KEY || "";
  if (!raycastDir) fail("RAYCAST_DIR is required");

  dbg("raycastDir=" + raycastDir);
  const dbFiles = listDbFiles(raycastDir);
  dbg("dbFiles=" + dbFiles.map((p) => path.basename(p)).join(","));
  if (dbFiles.length === 0) fail("no DB files found under " + raycastDir);

  const binding = loadBinding();

  let tokens = {};
  let prefs = {};

  // Path A: if Raycast's binding still exports a Database constructor, use the legacy "extensions" table query.
  const Database = getDatabaseCtor(binding);
  if (Database) {
    dbg("using Database ctor path");
    let db = null;
    for (const dbPath of dbFiles) {
      const candidate = tryOpenWithDatabase(Database, dbPath, backendKey);
      if (!candidate) continue;
      if (hasExtensionsTable(candidate)) {
        db = candidate;
        break;
      }
      try {
        if (candidate && typeof candidate.close === "function") candidate.close();
      } catch {
        // ignore
      }
    }

    if (db) {
      const rows = queryExtensionsTable(db);
      for (const row of rows || []) {
        const name = row && row.name;
        if (typeof name !== "string" || !name) continue;

        if (row && row.tokenSets != null) {
          const sets = parseTokenSets(row.tokenSets);
          if (sets && Array.isArray(sets) && sets.length > 0) tokens[name] = sets;
        }
        if (row && row.preferences != null) {
          const p = parsePreferences(row.preferences);
          if (p && Object.keys(p).length > 0) prefs[name] = p;
        }
      }

      process.stdout.write(JSON.stringify({ tokens, prefs }));
      return;
    }

    dbg("Database ctor path did not find extensions table");
  }

  // Path B: newer Raycast builds expose DatabaseClient + repositories (no direct SQL surface).
  const client = createDbClient(binding, raycastDir, backendKey);
  if (!client) fail("could not create DatabaseClient");

  // If initReport exists, call it with a noop callback (some builds require it).
  try {
    if (client && typeof client.initReport === "function") {
      dbg("calling DatabaseClient.initReport(noop)");
      await maybeAwait(client.initReport(() => {}));
    }
  } catch (err) {
    dbg("initReport failed: " + (err && err.message ? err.message : String(err)));
  }

  const rows = await getNodeExtensionsRows(client);
  if (!rows) fail("could not read node extensions via DatabaseClient");

  try {
    dbg("nodeExtensions rows=" + String(rows.length));
    if (DEBUG && rows.length > 0) {
      const r0 = rows[0];
      if (r0 && typeof r0 === "object") {
        dbg("nodeExtensions row[0] keys=" + Object.getOwnPropertyNames(r0).join(","));
      } else {
        dbg("nodeExtensions row[0] typeof=" + typeof r0);
      }
    }
  } catch {
    // ignore
  }

  for (const row of rows || []) {
    const name = getExtName(row);
    if (!name) continue;

    const sets = parseTokenSets(row && (row.tokenSets ?? row.token_sets ?? row.tokens ?? row.oauthTokens));
    if (sets && Array.isArray(sets) && sets.length > 0) tokens[name] = sets;

    const p = parsePreferences(row && (row.preferences ?? row.prefs ?? row.userPreferences));
    if (p && Object.keys(p).length > 0) prefs[name] = p;
  }

  // Best-effort: ask the backend to close gracefully so node.exe can exit promptly.
  try {
    if (client && typeof client.shutdown === "function") {
      dbg("calling DatabaseClient.shutdown()");
      await maybeAwait(client.shutdown());
    }
  } catch {
    // ignore
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
      RAYCAST_BACKEND_DB_KEY: key || "",
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
