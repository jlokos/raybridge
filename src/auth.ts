import { execFileSync, execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, unlinkSync, mkdtempSync, rmdirSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";

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


/**
 * Read the database encryption key from macOS Keychain, derive the
 * passphrase using Raycast's salt, and return it.
 */
function getDatabasePassphrase(): string {
  const keyHex = execFileSync("security", [
    "find-generic-password",
    "-s",
    "Raycast",
    "-a",
    "database_key",
    "-w",
  ], { encoding: "utf-8" }).trim();

  return createHash("sha256")
    .update(keyHex + RAYCAST_SALT)
    .digest("hex");
}

/**
 * Query Raycast's encrypted SQLite database using sqlcipher CLI.
 * Uses unique temp directory per query and includes retry logic for transient errors.
 */
function queryDB(passphrase: string, sql: string, retries = 3): any[] {
  const dbDir = join(
    homedir(),
    "Library",
    "Application Support",
    "com.raycast.macos"
  );
  const dbPath = join(dbDir, "raycast-enc.sqlite");

  // Create unique temp directory per query to avoid conflicts
  const tmpDir = mkdtempSync(join(tmpdir(), "raybridge-db-"));
  const tmpDb = join(tmpDir, "raycast-enc.sqlite");

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
    try {
      // Copy all DB files as close together as possible
      copyFileSync(dbPath, tmpDb);
      for (const ext of ["-wal", "-shm"]) {
        const src = dbPath + ext;
        if (existsSync(src)) copyFileSync(src, tmpDb + ext);
      }

      const input = `PRAGMA key = '${passphrase}';\n.mode json\n${sql}`;
      const result = execSync(`sqlcipher "${tmpDb}"`, {
        input,
        encoding: "utf-8",
        maxBuffer: 10 * 1024 * 1024,
      });

      cleanup();

      const jsonStr = result.startsWith("ok\n") ? result.slice(3) : result;
      try {
        return JSON.parse(jsonStr.trim());
      } catch {
        return [];
      }
    } catch (err: any) {
      const message = err?.message || String(err);
      const isTransient =
        message.includes("database is locked") ||
        message.includes("database disk image is malformed") ||
        message.includes("no such table");

      if (isTransient && attempt < retries) {
        // Brief delay before retry - give Raycast time to finish writing
        const delay = 50 * attempt;
        if (typeof Bun !== "undefined" && Bun.sleepSync) {
          Bun.sleepSync(delay);
        } else {
          const start = Date.now();
          while (Date.now() - start < delay) {
            // Busy wait fallback
          }
        }
        continue;
      }

      cleanup();
      throw err;
    }
  }

  cleanup();
  return [];
}

/**
 * Load OAuth token sets for all extensions from Raycast's encrypted DB.
 * Returns a map of extension name -> array of token sets.
 */
export function loadRaycastTokens(): Map<string, TokenSet[]> {
  const tokens = new Map<string, TokenSet[]>();

  try {
    const passphrase = getDatabasePassphrase();
    const rows = queryDB(
      passphrase,
      "SELECT name, tokenSets FROM extensions WHERE tokenSets IS NOT NULL AND tokenSets != '';"
    );

    for (const row of rows) {
      if (!row.name || !row.tokenSets) continue;
      try {
        const parsed = JSON.parse(row.tokenSets);
        const sets = Array.isArray(parsed) ? parsed : [parsed];
        tokens.set(row.name, sets as TokenSet[]);
      } catch {
        continue;
      }
    }
  } catch (err) {
    console.error("ray-ai-tools: Could not read Raycast OAuth tokens:", err);
  }

  return tokens;
}

/**
 * Load extension preferences from Raycast's encrypted DB.
 * Returns a map of extension name -> preference key-value pairs.
 */
export function loadRaycastPreferences(): Record<string, Record<string, unknown>> {
  const prefs: Record<string, Record<string, unknown>> = {};

  try {
    const passphrase = getDatabasePassphrase();
    const rows = queryDB(
      passphrase,
      "SELECT name, preferences FROM extensions WHERE preferences IS NOT NULL AND preferences != '';"
    );

    for (const row of rows) {
      if (!row.name || !row.preferences) continue;
      try {
        const parsed = JSON.parse(row.preferences);
        // Preferences are stored as array of {name, value, ...} objects
        const prefObj: Record<string, unknown> = {};
        if (Array.isArray(parsed)) {
          for (const pref of parsed) {
            if (pref.name && pref.value !== undefined) {
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
    console.error("ray-ai-tools: Could not read Raycast preferences:", err);
  }

  return prefs;
}
