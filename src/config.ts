import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import type { ExtensionEntry } from "./discovery.js";

export interface ExtensionConfig {
  enabled: boolean;
  tools?: string[];
}

export interface ToolsConfig {
  mode: "blocklist" | "allowlist";
  extensions: Record<string, ExtensionConfig>;
}

const CONFIG_DIR = join(homedir(), ".config", "raybridge");
const CONFIG_PATH = join(CONFIG_DIR, "tools.json");

export function getConfigPath(): string {
  return CONFIG_PATH;
}

export async function loadToolsConfig(): Promise<ToolsConfig> {
  try {
    const content = await readFile(CONFIG_PATH, "utf-8");
    return JSON.parse(content);
  } catch {
    // Return default config if file doesn't exist
    return {
      mode: "blocklist",
      extensions: {},
    };
  }
}

export async function saveToolsConfig(config: ToolsConfig): Promise<void> {
  await mkdir(dirname(CONFIG_PATH), { recursive: true });
  await writeFile(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n");
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
