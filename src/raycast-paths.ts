import { homedir } from "node:os";
import { join } from "node:path";
import { existsSync, readdirSync } from "node:fs";

function envPath(name: string): string | null {
  const v = process.env[name];
  if (!v) return null;
  const trimmed = v.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function getRaycastDataDir(): string {
  // Allow explicit override for unusual installs / portable environments.
  const override = envPath("RAYBRIDGE_RAYCAST_DATA_DIR");
  if (override) return override;

  if (process.platform === "win32") {
    const localAppDataBase = envPath("LOCALAPPDATA") || join(homedir(), "AppData", "Local");

    const hasDbFiles = (dir: string): boolean => {
      try {
        if (!existsSync(dir)) return false;
        const entries = readdirSync(dir);
        return entries.some((n) => /\.(db|sqlite|sqlite3)$/i.test(n) && !/-wal$|-shm$/i.test(n));
      } catch {
        return false;
      }
    };

    const direct = join(localAppDataBase, "Raycast");
    if (hasDbFiles(direct)) return direct;

    // Microsoft Store/AppX installs often store app data under %LOCALAPPDATA%\\Packages\\<family>\\...
    const packagesRoot = join(localAppDataBase, "Packages");
    try {
      const dirs = readdirSync(packagesRoot, { withFileTypes: true } as any)
        .filter((d: any) => d?.isDirectory?.())
        .map((d: any) => d.name as string)
        .filter((name) => name.toLowerCase().startsWith("raycast.raycast"));

      for (const name of dirs) {
        const pkgDir = join(packagesRoot, name);
        const candidates = [
          join(pkgDir, "LocalState"),
          join(pkgDir, "LocalState", "Raycast"),
          join(pkgDir, "LocalCache", "Local"),
          join(pkgDir, "LocalCache", "Local", "Raycast"),
        ];
        for (const c of candidates) {
          if (hasDbFiles(c)) return c;
        }
      }
    } catch {
      // ignore
    }

    // Fall back to the most common location even if empty.
    return direct;
  }

  if (process.platform === "darwin") {
    return join(homedir(), "Library", "Application Support", "com.raycast.macos");
  }

  // Linux is untested; default to the common config dir pattern.
  return join(homedir(), ".config", "raycast");
}

export function getRaycastExtensionsDir(): string {
  const override = envPath("RAYBRIDGE_RAYCAST_EXTENSIONS_DIR");
  if (override) return override;

  // Raycast for Windows has used both raycast and raycast-x historically. Prefer an existing dir.
  if (process.platform === "win32") {
    const a = join(homedir(), ".config", "raycast-x", "extensions");
    const b = join(homedir(), ".config", "raycast", "extensions");
    const hasAnyExtension = (dir: string): boolean => {
      try {
        if (!existsSync(dir)) return false;
        const entries = readdirSync(dir, { withFileTypes: true } as any);
        for (const ent of entries) {
          if (!ent?.isDirectory?.()) continue;
          const pkg = join(dir, ent.name, "package.json");
          if (existsSync(pkg)) return true;
        }
        return false;
      } catch {
        return false;
      }
    };

    if (hasAnyExtension(a)) return a;
    if (hasAnyExtension(b)) return b;
    if (existsSync(a)) return a;
    if (existsSync(b)) return b;
    return a;
  }

  // Raycast for macOS uses raycast.
  return join(homedir(), ".config", "raycast", "extensions");
}
