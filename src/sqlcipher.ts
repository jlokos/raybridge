import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, delimiter as PATH_DELIM, dirname, join } from "node:path";
import { homedir, tmpdir } from "node:os";

const SQLITE3MC_VERSION = "2.2.7";
const SQLITE3MC_SQLITE_VERSION = "3.51.2";
const SQLITE3MC_TAG = `v${SQLITE3MC_VERSION}`;
const SQLITE3MC_REPO = "utelle/SQLite3MultipleCiphers";

const SQLITE3MC_SHA256_WIN64_ZIP =
  "11dc5073e371f292dc80fe5f01d3fe16a0160ffff6a1e81b90631883fbba5588";
const SQLITE3MC_SHA256_WIN32_ZIP =
  "90b371d01e5d75bf77e52f21cc1b9673a4049a1dffd462fdf9992873d4af08c6";

function envStr(name: string): string | undefined {
  const v = process.env[name];
  return v && v.trim().length > 0 ? v.trim() : undefined;
}

function getCacheDir(): string {
  const override = envStr("RAYBRIDGE_CACHE_DIR");
  if (override) return override;

  const home = homedir();
  if (process.platform === "win32") {
    const local = process.env.LOCALAPPDATA || join(home, "AppData", "Local");
    return join(local, "raybridge");
  }
  const xdg = envStr("XDG_CACHE_HOME");
  return join(xdg || join(home, ".cache"), "raybridge");
}

function findOnPath(candidateNames: string[]): string | null {
  const pathEnv = process.env.PATH || "";
  const dirs = pathEnv.split(PATH_DELIM).filter(Boolean);

  for (const dir of dirs) {
    for (const name of candidateNames) {
      const full = join(dir, name);
      try {
        if (existsSync(full)) return full;
      } catch {
        // Ignore broken PATH entries
      }
    }
  }
  return null;
}

async function downloadToFile(url: string, destPath: string, expectedSha256?: string): Promise<void> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Download failed (${res.status}): ${url}`);
  }
  const bytes = new Uint8Array(await res.arrayBuffer());

  if (expectedSha256) {
    const sha = createHash("sha256").update(bytes).digest("hex");
    if (sha.toLowerCase() !== expectedSha256.toLowerCase()) {
      throw new Error(`SHA256 mismatch for ${url} (expected ${expectedSha256}, got ${sha})`);
    }
  } else if (envStr("RAYBRIDGE_SQLCIPHER_ALLOW_INSECURE_DOWNLOAD") !== "1") {
    throw new Error(
      "Refusing to download sqlcipher without SHA256. Set RAYBRIDGE_SQLCIPHER_SHA256 or set RAYBRIDGE_SQLCIPHER_ALLOW_INSECURE_DOWNLOAD=1."
    );
  }

  mkdirSync(dirname(destPath), { recursive: true });
  const tmp = `${destPath}.tmp-${Date.now()}`;
  writeFileSync(tmp, bytes);
  renameSync(tmp, destPath);

  // Ensure it's executable on Unix-y platforms.
  if (process.platform !== "win32") {
    try {
      chmodSync(destPath, 0o755);
    } catch {
      // Best-effort.
    }
  }
}

function encodePowerShell(script: string): string {
  // PowerShell expects UTF-16LE for -EncodedCommand.
  return Buffer.from(script, "utf16le").toString("base64");
}

function expandArchive(zipPath: string, destDir: string): void {
  const ps = `
$ErrorActionPreference = 'Stop'
$zip = '${zipPath.replace(/'/g, "''")}'
$dest = '${destDir.replace(/'/g, "''")}'
Expand-Archive -LiteralPath $zip -DestinationPath $dest -Force
`.trim();

  execFileSync("powershell.exe", ["-NoProfile", "-EncodedCommand", encodePowerShell(ps)], {
    stdio: "ignore",
  });
}

function sqlite3mcSpecForArch(): {
  assetName: string;
  zipUrl: string;
  zipSha256: string;
  exeInZip: string;
  dllInZip: string;
} {
  const is64Bit = process.arch === "x64" || process.arch === "arm64";
  const winFlavor = is64Bit ? "win64" : "win32";
  const assetName = `sqlite3mc-${SQLITE3MC_VERSION}-sqlite-${SQLITE3MC_SQLITE_VERSION}-${winFlavor}.zip`;
  const zipUrl = `https://github.com/${SQLITE3MC_REPO}/releases/download/${SQLITE3MC_TAG}/${assetName}`;
  const zipSha256 = is64Bit ? SQLITE3MC_SHA256_WIN64_ZIP : SQLITE3MC_SHA256_WIN32_ZIP;
  const exeInZip = is64Bit ? "bin/sqlite3mc_shell_x64.exe" : "bin/sqlite3mc_shell.exe";
  const dllInZip = is64Bit ? "dll/sqlite3mc_x64.dll" : "dll/sqlite3mc.dll";
  return { assetName, zipUrl, zipSha256, exeInZip, dllInZip };
}

async function ensureWindowsSqlite3mcInstalled(sqlcipherDestPath: string): Promise<void> {
  const cacheDir = dirname(dirname(sqlcipherDestPath));
  const { assetName, zipUrl, zipSha256, exeInZip, dllInZip } = sqlite3mcSpecForArch();

  mkdirSync(dirname(sqlcipherDestPath), { recursive: true });
  const dllDestPath = join(dirname(sqlcipherDestPath), basename(dllInZip));

  if (existsSync(sqlcipherDestPath) && existsSync(dllDestPath)) return;

  const downloadDir = join(cacheDir, "downloads");
  mkdirSync(downloadDir, { recursive: true });
  const zipPath = join(downloadDir, assetName);

  if (!existsSync(zipPath)) {
    await downloadToFile(zipUrl, zipPath, zipSha256);
  }

  const extractDir = mkdtempSync(join(tmpdir(), "raybridge-sqlite3mc-"));
  try {
    expandArchive(zipPath, extractDir);

    const exeSrcPath = join(extractDir, ...exeInZip.split("/"));
    const dllSrcPath = join(extractDir, ...dllInZip.split("/"));
    if (!existsSync(exeSrcPath) || !existsSync(dllSrcPath)) {
      throw new Error(`sqlite3mc archive missing expected files (${exeInZip}, ${dllInZip})`);
    }

    const exeTmp = `${sqlcipherDestPath}.tmp-${Date.now()}`;
    const dllTmp = `${dllDestPath}.tmp-${Date.now()}`;
    copyFileSync(exeSrcPath, exeTmp);
    copyFileSync(dllSrcPath, dllTmp);
    renameSync(exeTmp, sqlcipherDestPath);
    renameSync(dllTmp, dllDestPath);
  } finally {
    try {
      rmSync(extractDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
  }
}

/**
 * Resolve a usable sqlcipher CLI path.
 *
 * Order:
 * 1) RAYBRIDGE_SQLCIPHER_PATH
 * 2) PATH (sqlcipher / sqlcipher.exe)
 * 3) Cache dir (downloaded)
 * 4) Download (if allowed)
 */
export async function resolveSqlcipherPath(): Promise<string> {
  const override = envStr("RAYBRIDGE_SQLCIPHER_PATH");
  if (override) return override;

  const candidates = process.platform === "win32"
    ? ["sqlcipher.exe", "sqlcipher", "sqlite3mc_shell_x64.exe", "sqlite3mc_shell.exe"]
    : ["sqlcipher"];
  const fromPath = findOnPath(candidates);
  if (fromPath) return fromPath;

  const cacheDir = getCacheDir();
  const binName = process.platform === "win32" ? "sqlcipher.exe" : "sqlcipher";
  const cached = join(cacheDir, "bin", binName);
  if (existsSync(cached)) return cached;

  if (envStr("RAYBRIDGE_NO_DOWNLOAD") === "1") {
    throw new Error(
      'sqlcipher not found and downloads disabled (RAYBRIDGE_NO_DOWNLOAD=1). Set RAYBRIDGE_SQLCIPHER_PATH or install sqlcipher.'
    );
  }

  // Windows: auto-install a pinned, portable SQLite3MultipleCiphers shell and treat it as our "sqlcipher" backend.
  // This avoids MSYS2 and other build dependencies for end users.
  if (process.platform === "win32") {
    await ensureWindowsSqlite3mcInstalled(cached);
    return cached;
  }

  // Non-Windows: prefer system package managers (brew/apt). Optional download is available if a direct URL is provided.
  const urlOverride = envStr("RAYBRIDGE_SQLCIPHER_URL");
  if (!urlOverride) {
    throw new Error(
      "sqlcipher not found. Install sqlcipher and ensure it's on PATH (macOS: `brew install sqlcipher`), or set RAYBRIDGE_SQLCIPHER_PATH. Optionally set RAYBRIDGE_SQLCIPHER_URL + RAYBRIDGE_SQLCIPHER_SHA256 to download a binary."
    );
  }

  const shaOverride = envStr("RAYBRIDGE_SQLCIPHER_SHA256");
  await downloadToFile(urlOverride, cached, shaOverride);
  return cached;
}
