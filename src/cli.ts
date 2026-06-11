#!/usr/bin/env bun


import { discoverExtensions, type ExtensionEntry } from "./discovery.js";
import { loadToolsConfig, filterExtensions, getConfigPath, type ToolsConfig } from "./config.js";

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
  if (config.mode === "blocklist") {
    return extConfig?.enabled !== false;
  } else {
    return extConfig?.enabled === true;
  }
}

function getEnabledToolCount(ext: ExtensionEntry, config: ToolsConfig): number {
  if (!isExtensionEnabled(ext, config)) return 0;
  const extConfig = config.extensions[ext.extensionName];
  if (!extConfig?.tools || extConfig.tools.length === 0) return ext.tools.length;
  return extConfig.tools.filter((t) => ext.tools.some((et) => et.name === t)).length;
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

    // Show individual tools if there's a tool filter
    if (extConfig?.tools && extConfig.tools.length > 0 && extConfig.tools.length < ext.tools.length) {
      for (const tool of ext.tools) {
        const toolEnabled = extConfig.tools.includes(tool.name);
        const toolStatus = toolEnabled ? "[x]" : "[ ]";
        console.log(`      ${toolStatus} ${tool.name}`);
      }
    }
  }
}

async function listExtensions(): Promise<void> {
  const [extensions, config] = await Promise.all([
    discoverExtensions(),
    loadToolsConfig(),
  ]);

  const filteredExtensions = filterExtensions(extensions, config);

  // Calculate totals
  const totalExts = extensions.length;
  const enabledExts = filteredExtensions.length;
  const totalTools = extensions.reduce((n, e) => n + e.tools.length, 0);
  const enabledTools = extensions.reduce((n, e) => n + getEnabledToolCount(e, config), 0);

  console.log(LOGO);
  console.log("");
  console.log(`Config: ${getConfigPath()}`);
  console.log(`Mode: ${config.mode}`);
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

/**
 * The interactive config TUI depends on optional packages (@opentui/*, react).
 * When they are not installed, dynamic-importing ./tui.js throws a
 * module-resolution error; detect that so we can show install guidance instead
 * of a raw stack trace.
 */
function isMissingTuiDependency(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const code = (err as { code?: string }).code;
  const message = (err as { message?: string }).message ?? "";
  const moduleNotFound =
    code === "ERR_MODULE_NOT_FOUND" ||
    code === "MODULE_NOT_FOUND" ||
    /cannot find (module|package)/i.test(message);
  return moduleNotFound && /@opentui|\breact\b/i.test(message);
}

async function main(): Promise<void> {
  const command = process.argv[2];

  switch (command) {
    case undefined:
    case "config": {
      try {
        const { launchTUI } = await import("./tui.js");
        await launchTUI();
      } catch (err) {
        if (isMissingTuiDependency(err)) {
          console.error(
            [
              "The interactive config UI requires optional dependencies that are not installed:",
              "  @opentui/core, @opentui/react, react",
              "",
              "Install them with your package manager, for example:",
              "  bun add @opentui/core @opentui/react react",
              "",
              "Or edit ~/.config/raybridge/tools.json directly (see docs/CONFIGURATION.md),",
              "and run `raybridge list` to see what is currently exposed.",
            ].join("\n")
          );
          process.exit(1);
        }
        throw err;
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
