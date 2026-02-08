/* eslint-disable no-console */
/**
 * Windows-only helper script executed by Raycast's bundled backend node runtime.
 *
 * The parent process sets:
 * - RAYCAST_DIR: Raycast data directory (contains main.db and related files)
 * - RAYCAST_BACKEND_DB_KEY: BackendDBKey from Windows Credential Manager
 *
 * This script must print ONLY JSON to stdout on success.
 */

const fs = require("node:fs");
const path = require("node:path");

function fail(msg) {
  process.stderr.write(String(msg || "unknown error") + "\n");
  process.exit(1);
}

function safeJsonParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function listDbFiles(dir) {
  try {
    const entries = fs.readdirSync(dir);
    return entries
      .filter((n) => n.toLowerCase().endsWith(".db"))
      .map((n) => path.join(dir, n));
  } catch {
    return [];
  }
}

function tryOpenWithBinding(dbPath, backendKey) {
  // Raycast ships a native module alongside node.exe. The exact API shape may vary by version.
  const bindingPath = path.join(process.cwd(), "data.win32-x64-msvc.node");
  if (!fs.existsSync(bindingPath)) return null;

  let binding;
  try {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    binding = require(bindingPath);
  } catch {
    return null;
  }

  const Database =
    (binding && (binding.Database || binding.default)) ||
    (typeof binding === "function" ? binding : null);
  if (typeof Database !== "function") return null;

  let db;
  try {
    // Common patterns across sqlite bindings.
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
  } catch {
    try {
      db = new Database(dbPath);
    } catch {
      return null;
    }
  }

  // Best-effort: set encryption key if the binding supports it.
  try {
    if (db && typeof db.pragma === "function") {
      const escaped = String(backendKey).replace(/'/g, "''");
      db.pragma(`key='${escaped}'`);
    }
  } catch {
    // ignore
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

function queryExtensions(db) {
  // Pull only what we need; tokenSets and preferences are JSON strings.
  if (typeof db.prepare !== "function") return [];
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

function main() {
  const raycastDir = process.env.RAYCAST_DIR;
  const backendKey = process.env.RAYCAST_BACKEND_DB_KEY;
  if (!raycastDir) fail("RAYCAST_DIR is required");
  if (!backendKey) fail("RAYCAST_BACKEND_DB_KEY is required");

  const dbFiles = listDbFiles(raycastDir);
  if (dbFiles.length === 0) fail(`no .db files found under ${raycastDir}`);

  let db = null;
  for (const dbPath of dbFiles) {
    const candidate = tryOpenWithBinding(dbPath, backendKey);
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

  if (!db) fail("could not open any Raycast DB with extensions table");

  const rows = queryExtensions(db);

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

  // Success: stdout must be only JSON.
  process.stdout.write(JSON.stringify({ tokens, prefs }));
}

main();

