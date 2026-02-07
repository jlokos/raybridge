import { join } from "node:path";
import { homedir } from "node:os";

function envPath(name: string): string | undefined {
  const v = process.env[name];
  return v && v.trim().length > 0 ? v.trim() : undefined;
}

export function getRaycastExtensionsDir(): string {
  // Override for non-standard installs.
  const override = envPath("RAYBRIDGE_RAYCAST_EXTENSIONS_DIR");
  if (override) return override;

  const home = homedir();
  // Raycast uses different config dirs across platforms.
  if (process.platform === "win32") {
    // Raycast for Windows stores extensions under ~/.config/raycast-x/extensions
    return join(home, ".config", "raycast-x", "extensions");
  }
  // macOS (and historical Linux experiments) use ~/.config/raycast/extensions
  return join(home, ".config", "raycast", "extensions");
}

export function getRaycastDataDir(): string {
  const override = envPath("RAYBRIDGE_RAYCAST_DATA_DIR");
  if (override) return override;

  const home = homedir();

  if (process.platform === "win32") {
    // Default Raycast data root on Windows.
    const local = process.env.LOCALAPPDATA || join(home, "AppData", "Local");
    return join(local, "Raycast");
  }

  if (process.platform === "darwin") {
    return join(home, "Library", "Application Support", "com.raycast.macos");
  }

  // Best-effort fallback. Users can override via RAYBRIDGE_RAYCAST_DATA_DIR.
  return join(home, ".config", "raycast");
}

