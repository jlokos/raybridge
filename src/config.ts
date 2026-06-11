import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import type { ExtensionEntry } from "./discovery.js";

export interface ExtensionConfig {
  enabled: boolean;
  tools?: string[];
  _note?: string;
}

export interface RaycastApiConfig {
  enableLocalStorage?: boolean;
  enableClipboard?: boolean;
  enableSystemActions?: boolean;
  enableDestructiveSystemActions?: boolean;
  enableAppleScript?: boolean;
  enableCommandLaunch?: boolean;
}

export interface ToolsConfig {
  _comment?: string;
  mode: "blocklist" | "allowlist";
  raycastApi?: RaycastApiConfig;
  extensions: Record<string, ExtensionConfig>;
}

const CONFIG_DIR = join(homedir(), ".config", "raybridge");
const CONFIG_PATH = join(CONFIG_DIR, "tools.json");

export function getConfigPath(): string {
  return CONFIG_PATH;
}

function cloneConfig(config: ToolsConfig): ToolsConfig {
  return JSON.parse(JSON.stringify(config));
}

export const SAFE_DEFAULT_CONFIG: ToolsConfig = {
  _comment: "Safe RayBridge defaults. Add tools intentionally in ~/.config/raybridge/tools.json.",
  mode: "allowlist",
  raycastApi: {
    enableLocalStorage: true,
    enableClipboard: false,
    enableSystemActions: false,
    enableDestructiveSystemActions: false,
    enableAppleScript: false,
    enableCommandLaunch: false,
  },
  extensions: {},
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function booleanOrDefault(value: unknown, defaultValue: boolean): boolean {
  return typeof value === "boolean" ? value : defaultValue;
}

function uniqueStringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const items = value.filter(
    (item): item is string => typeof item === "string" && item.trim().length > 0
  );
  return items.length > 0 ? [...new Set(items)] : undefined;
}

export function normalizeToolsConfig(raw: unknown): ToolsConfig {
  const defaults = cloneConfig(SAFE_DEFAULT_CONFIG);
  if (!isRecord(raw)) return defaults;

  const mode = raw.mode === "blocklist" ? "blocklist" : "allowlist";
  const rawApi = isRecord(raw.raycastApi) ? raw.raycastApi : {};
  const defaultApi = defaults.raycastApi ?? {};
  const raycastApi: RaycastApiConfig = {
    enableLocalStorage: booleanOrDefault(
      rawApi.enableLocalStorage,
      defaultApi.enableLocalStorage ?? true
    ),
    enableClipboard: booleanOrDefault(
      rawApi.enableClipboard,
      defaultApi.enableClipboard ?? false
    ),
    enableSystemActions: booleanOrDefault(
      rawApi.enableSystemActions,
      defaultApi.enableSystemActions ?? false
    ),
    enableDestructiveSystemActions: booleanOrDefault(
      rawApi.enableDestructiveSystemActions,
      defaultApi.enableDestructiveSystemActions ?? false
    ),
    enableAppleScript: booleanOrDefault(
      rawApi.enableAppleScript,
      defaultApi.enableAppleScript ?? false
    ),
    enableCommandLaunch: booleanOrDefault(
      rawApi.enableCommandLaunch,
      defaultApi.enableCommandLaunch ?? false
    ),
  };

  const extensions: Record<string, ExtensionConfig> = {};
  const rawExtensions = isRecord(raw.extensions) ? raw.extensions : {};
  for (const [extensionName, rawExtensionConfig] of Object.entries(rawExtensions)) {
    if (!extensionName.trim() || !isRecord(rawExtensionConfig)) continue;

    const tools = uniqueStringList(rawExtensionConfig.tools);
    const config: ExtensionConfig = {
      enabled: booleanOrDefault(rawExtensionConfig.enabled, mode === "blocklist"),
    };
    if (tools) config.tools = tools;
    if (typeof rawExtensionConfig._note === "string") {
      config._note = rawExtensionConfig._note;
    }
    extensions[extensionName] = config;
  }

  return {
    ...(typeof raw._comment === "string" ? { _comment: raw._comment } : {}),
    mode,
    raycastApi,
    extensions,
  };
}

export async function loadToolsConfig(): Promise<ToolsConfig> {
  try {
    const content = await readFile(CONFIG_PATH, "utf-8");
    return normalizeToolsConfig(JSON.parse(content));
  } catch {
    return cloneConfig(SAFE_DEFAULT_CONFIG);
  }
}

export async function saveToolsConfig(config: ToolsConfig): Promise<void> {
  await mkdir(dirname(CONFIG_PATH), { recursive: true });
  let existing: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(await readFile(CONFIG_PATH, "utf-8"));
    if (isRecord(parsed)) existing = parsed;
  } catch {
    existing = {};
  }

  const knownKeys = new Set(["_comment", "mode", "raycastApi", "extensions"]);
  const preserved = Object.fromEntries(
    Object.entries(existing).filter(([key]) => !knownKeys.has(key))
  );
  await writeFile(
    CONFIG_PATH,
    JSON.stringify({ ...preserved, ...normalizeToolsConfig(config) }, null, 2) + "\n"
  );
}

export function filterExtensions(
  extensions: ExtensionEntry[],
  config: ToolsConfig
): ExtensionEntry[] {
  return extensions
    .filter((ext) => {
      const extConfig = config.extensions[ext.extensionName];

      if (config.mode === "blocklist") {
        // In blocklist mode: enabled by default unless explicitly disabled
        if (!extConfig) return true;
        return extConfig.enabled !== false;
      } else {
        // In allowlist mode: disabled by default unless explicitly enabled
        if (!extConfig) return false;
        return extConfig.enabled === true;
      }
    })
    .map((ext) => {
      const extConfig = config.extensions[ext.extensionName];

      // If no tool-level filtering, return extension as-is
      if (!extConfig?.tools || extConfig.tools.length === 0) {
        return ext;
      }

      // Filter tools based on config
      const allowedTools = new Set(extConfig.tools);
      return {
        ...ext,
        tools: ext.tools.filter((tool) => allowedTools.has(tool.name)),
      };
    })
    .filter((ext) => ext.tools.length > 0); // Remove extensions with no tools left
}
