import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import type { ExtensionEntry } from "./discovery.js";

export interface ExtensionConfig {
  enabled: boolean;
  disabledTools?: string[];
}

export interface ToolsConfig {
  extensions: Record<string, ExtensionConfig>;
}

/** Raw config shape as loaded from JSON (may include legacy fields). */
export interface RawToolsConfig {
  mode?: "blocklist" | "allowlist";
  extensions?: Record<string, { enabled?: boolean; tools?: string[]; disabledTools?: string[] }>;
}

const CONFIG_DIR = join(homedir(), ".config", "raybridge");
const CONFIG_PATH = join(CONFIG_DIR, "tools.json");

export function getConfigPath(): string {
  return CONFIG_PATH;
}

export async function loadToolsConfig(): Promise<RawToolsConfig> {
  try {
    const content = await readFile(CONFIG_PATH, "utf-8");
    return JSON.parse(content) as RawToolsConfig;
  } catch {
    // Return default config if file doesn't exist
    return { extensions: {} };
  }
}

export async function saveToolsConfig(config: ToolsConfig): Promise<void> {
  await mkdir(dirname(CONFIG_PATH), { recursive: true });
  await writeFile(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n");
}

export interface NormalizeResult {
  config: ToolsConfig;
  didMigrate: boolean;
}

/**
 * Normalizes raw config (possibly legacy) to blocklist-only ToolsConfig.
 * Converts mode: "allowlist" and tools allowlist into blocklist semantics.
 */
export function normalizeLegacyConfig(
  raw: RawToolsConfig,
  extensions: ExtensionEntry[]
): NormalizeResult {
  const extMap = new Map(extensions.map((e) => [e.extensionName, e]));
  let didMigrate = false;
  const isLegacyAllowlist = raw.mode === "allowlist";
  if (isLegacyAllowlist) didMigrate = true;

  const extensionsOut: Record<string, ExtensionConfig> = {};
  const rawExts = raw.extensions ?? {};

  for (const [extName, rawExt] of Object.entries(rawExts)) {
    if (!rawExt || typeof rawExt !== "object") continue;
    if (!extMap.has(extName)) continue; // Skip extensions not in discovery

    // Extension enabled: blocklist default true, allowlist default false
    let enabled: boolean;
    if (isLegacyAllowlist) {
      enabled = rawExt.enabled === true;
      didMigrate = true;
    } else {
      enabled = rawExt.enabled !== false;
    }

    // Tool-level: convert tools allowlist -> disabledTools blocklist if needed
    let disabledTools: string[] | undefined;
    const ext = extMap.get(extName);
    const toolNames = ext ? ext.tools.map((t) => t.name) : [];

    if (rawExt.disabledTools && Array.isArray(rawExt.disabledTools) && rawExt.disabledTools.length > 0) {
      disabledTools = rawExt.disabledTools.filter((t): t is string => typeof t === "string");
    } else if (rawExt.tools && Array.isArray(rawExt.tools) && rawExt.tools.length > 0) {
      // Legacy: tools is allowlist -> compute disabledTools
      const allowed = new Set(rawExt.tools.filter((t): t is string => typeof t === "string"));
      disabledTools = toolNames.filter((n) => !allowed.has(n));
      if (disabledTools.length > 0) didMigrate = true;
    }

    if (!enabled) {
      extensionsOut[extName] = { enabled: false };
    } else if (disabledTools && disabledTools.length > 0) {
      extensionsOut[extName] = { enabled: true, disabledTools };
    }
  }

  const config: ToolsConfig = { extensions: extensionsOut };
  return { config, didMigrate };
}

export function filterExtensions(
  extensions: ExtensionEntry[],
  config: ToolsConfig
): ExtensionEntry[] {
  return extensions
    .filter((ext) => {
      const extConfig = config.extensions[ext.extensionName];
      if (!extConfig) return true;
      return extConfig.enabled !== false;
    })
    .map((ext) => {
      const extConfig = config.extensions[ext.extensionName];
      if (!extConfig?.disabledTools || extConfig.disabledTools.length === 0) {
        return ext;
      }
      const blocked = new Set(extConfig.disabledTools);
      return {
        ...ext,
        tools: ext.tools.filter((tool) => !blocked.has(tool.name)),
      };
    })
    .filter((ext) => ext.tools.length > 0);
}
