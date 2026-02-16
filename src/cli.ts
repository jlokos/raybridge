#!/usr/bin/env bun

import { discoverExtensions, type ExtensionEntry } from "./discovery.js";
import { runWithSpinner, startSpinner } from "./spinner.js";
import {
  loadToolsConfig,
  saveToolsConfig,
  filterExtensions,
  getConfigPath,
  normalizeLegacyConfig,
  type ToolsConfig,
} from "./config.js";

const LOGO = `
██████╗  █████╗ ██╗   ██╗██████╗ ██████╗ ██╗██████╗  ██████╗ ███████╗
██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝
██████╔╝███████║ ╚████╔╝ ██████╔╝██████╔╝██║██║  ██║██║  ███╗█████╗
██╔══██╗██╔══██║  ╚██╔╝  ██╔══██╗██╔══██╗██║██║  ██║██║   ██║██╔══╝
██║  ██║██║  ██║   ██║   ██████╔╝██║  ██║██║██████╔╝╚██████╔╝███████╗
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
`.trim();

function isExtensionEnabled(ext: ExtensionEntry, config: ToolsConfig): boolean {
  const extConfig = config.extensions[ext.extensionName];
  return extConfig?.enabled !== false;
}

function getEnabledToolCount(ext: ExtensionEntry, config: ToolsConfig): number {
  if (!isExtensionEnabled(ext, config)) return 0;
  const extConfig = config.extensions[ext.extensionName];
  if (!extConfig?.disabledTools || extConfig.disabledTools.length === 0) return ext.tools.length;
  return ext.tools.filter((t) => !extConfig.disabledTools!.includes(t.name)).length;
}

function printSection(
  label: string,
  extensions: ExtensionEntry[],
  config: ToolsConfig
): void {
  if (extensions.length === 0) return;

  const enabledCount = extensions.filter((e) => isExtensionEnabled(e, config)).length;
  const totalTools = extensions.reduce((n, e) => n + e.tools.length, 0);
  const enabledTools = extensions.reduce((n, e) => n + getEnabledToolCount(e, config), 0);

  console.log(`\n${label}`);
  console.log(`  ${enabledCount}/${extensions.length} extensions, ${enabledTools}/${totalTools} tools`);
  console.log("");

  for (const ext of extensions) {
    const enabled = isExtensionEnabled(ext, config);
    const extConfig = config.extensions[ext.extensionName];
    const enabledToolCount = getEnabledToolCount(ext, config);
    const totalToolCount = ext.tools.length;
    const status = enabled ? "[x]" : "[ ]";
    const toolStats = enabled && enabledToolCount < totalToolCount ? ` (${enabledToolCount}/${totalToolCount})` : "";

    console.log(`  ${status} ${ext.extensionTitle} - ${totalToolCount} tool${totalToolCount !== 1 ? "s" : ""}${toolStats}`);

    // Show individual tools if there are disabled tools
    if (extConfig?.disabledTools && extConfig.disabledTools.length > 0) {
      for (const tool of ext.tools) {
        const toolEnabled = !extConfig.disabledTools.includes(tool.name);
        const toolStatus = toolEnabled ? "[x]" : "[ ]";
        console.log(`      ${toolStatus} ${tool.name}`);
      }
    }
  }
}

async function listExtensions(): Promise<void> {
  const { extensions, config } = await runWithSpinner(
    "Loading extensions...",
    async () => {
      const [exts, rawConfig] = await Promise.all([
        discoverExtensions(),
        loadToolsConfig(),
      ]);
      const { config: cfg, didMigrate } = normalizeLegacyConfig(rawConfig, exts);
      if (didMigrate) {
        await saveToolsConfig(cfg);
        console.error("raybridge: Migrated config to blocklist-only format");
      }
      return { extensions: exts, config: cfg };
    },
    process.stdout
  );

  const filteredExtensions = filterExtensions(extensions, config);

  // Calculate totals
  const totalExts = extensions.length;
  const enabledExts = filteredExtensions.length;
  const totalTools = extensions.reduce((n, e) => n + e.tools.length, 0);
  const enabledTools = extensions.reduce((n, e) => n + getEnabledToolCount(e, config), 0);

  console.log(LOGO);
  console.log("");
  console.log(`Config: ${getConfigPath()}`);
  console.log(`Total: ${enabledExts}/${totalExts} extensions, ${enabledTools}/${totalTools} tools`);

  printSection("Extensions", extensions, config);
}

function showHelp(): void {
  console.log(`
RayBridge - Bridge Raycast extensions to MCP

Usage:
  raybridge [command]

Commands:
  config    Launch interactive TUI to configure extensions (default)
  list      List all extensions and their status
  help      Show this help message

Examples:
  raybridge           # Launch TUI
  raybridge config    # Launch TUI
  raybridge list      # Show extensions list
`);
}

async function main(): Promise<void> {
  const command = process.argv[2];

  switch (command) {
    case undefined:
    case "config": {
      const stopSpinner = startSpinner("Launching RayBridge...", process.stdout, "orbit");
      try {
        const { launchTUI } = await import("./tui.js");
        await launchTUI({ onReady: stopSpinner });
      } finally {
        stopSpinner();
      }
      break;
    }
    case "list":
      await listExtensions();
      break;
    case "help":
    case "--help":
    case "-h":
      showHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      showHelp();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
