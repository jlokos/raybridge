import { watch, type FSWatcher } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { getRaycastDataDir, getRaycastExtensionsDir } from "./raycast-paths.js";

export interface WatcherOptions {
  onReload: () => Promise<boolean>; // Returns true if tools changed
  getServers: () => Server[]; // Get all active servers to notify
  debounceMs?: number;
}

export function startExtensionWatcher(options: WatcherOptions): FSWatcher[] {
  const { onReload, getServers, debounceMs = 1000 } = options;

  // Paths to watch
  const home = homedir();
  const extensionsDir = getRaycastExtensionsDir();
  const raycastSupportDir = getRaycastDataDir();
  const raybridgeConfigDir = join(home, ".config", "raybridge");
  const rayAiToolsConfigDir = join(home, ".config", "ray-ai-tools");

  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let isReloading = false;

  const triggerReload = async (source: string) => {
    if (isReloading) return;
    isReloading = true;

    try {
      console.error(`raybridge: Detected change in ${source}, reloading...`);
      const changed = await onReload();
      if (changed) {
        const servers = getServers();
        console.error(
          `raybridge: Tools changed, notifying ${servers.length} client(s)`
        );
        for (const server of servers) {
          try {
            await server.notification({
              method: "notifications/tools/list_changed",
            });
          } catch (err: any) {
            // Client may not support notifications or be disconnected
            console.error(`raybridge: Failed to notify client: ${err.message}`);
          }
        }
      }
    } catch (err: any) {
      console.error(`raybridge: Reload failed: ${err.message}`);
    } finally {
      isReloading = false;
    }
  };

  const debouncedReload = (source: string) => {
    if (debounceTimer) {
      clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      triggerReload(source);
    }, debounceMs);
  };

  const watchers: FSWatcher[] = [];

  // Watch extensions directory
  try {
    const extWatcher = watch(extensionsDir, { recursive: true }, (_event, filename) => {
      // Only trigger on relevant files
      const f = filename || "";
      if (f && !f.endsWith("package.json") && !f.includes("/tools/") && !f.includes("\\tools\\")) {
        return;
      }
      debouncedReload(filename || "extensions");
    });
    watchers.push(extWatcher);
    console.error(`raybridge: Watching ${extensionsDir}`);
  } catch (err: any) {
    console.error(`raybridge: Could not watch extensions dir: ${err.message}`);
  }

  // Watch Raycast support directory (for encrypted DB with OAuth tokens/prefs)
  try {
    const raycastWatcher = watch(raycastSupportDir, {}, (_event, filename) => {
      // Only trigger on database files
      if (filename && (filename.includes(".db") || filename === "encryptedLocalStorage")) {
        debouncedReload(`Raycast DB (${filename})`);
      }
    });
    watchers.push(raycastWatcher);
    console.error(`raybridge: Watching ${raycastSupportDir}`);
  } catch (err: any) {
    console.error(`raybridge: Could not watch Raycast dir: ${err.message}`);
  }

  // Watch raybridge config directory
  try {
    const configWatcher = watch(raybridgeConfigDir, {}, (_event, filename) => {
      if (filename?.endsWith(".json")) {
        debouncedReload(`config (${filename})`);
      }
    });
    watchers.push(configWatcher);
    console.error(`raybridge: Watching ${raybridgeConfigDir}`);
  } catch (err: any) {
    // Config dir might not exist
  }

  // Watch ray-ai-tools config directory (legacy)
  try {
    const legacyWatcher = watch(rayAiToolsConfigDir, {}, (_event, filename) => {
      if (filename?.endsWith(".json")) {
        debouncedReload(`preferences (${filename})`);
      }
    });
    watchers.push(legacyWatcher);
    console.error(`raybridge: Watching ${rayAiToolsConfigDir}`);
  } catch (err: any) {
    // Config dir might not exist
  }

  return watchers;
}
