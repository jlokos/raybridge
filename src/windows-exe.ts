import { existsSync } from "node:fs";
import { join } from "node:path";

function envPath(name: string): string | null {
  const v = process.env[name];
  if (!v) return null;
  const trimmed = v.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * Resolve a PowerShell executable path.
 *
 * We use PowerShell for Windows Credential Manager probing and AppX queries.
 * Keep this conservative: prefer the in-box Windows PowerShell when present.
 */
export function resolveWindowsPowerShellExe(): string {
  const override = envPath("RAYBRIDGE_POWERSHELL_EXE");
  if (override) return override;

  // Prefer explicit system path if available.
  const systemRoot = envPath("SystemRoot");
  if (systemRoot) {
    const ps = join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    if (existsSync(ps)) return ps;
  }

  // Fall back to PATH resolution.
  return "powershell.exe";
}

