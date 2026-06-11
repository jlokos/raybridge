import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { ToolDef } from "./index.js";
import type { ToolsConfig } from "./config.js";

export const RAYBRIDGE_TOOL_NAME = "raybridge";

export interface CatalogTool {
  name: string;
  title: string;
  description: string;
  enabled: boolean;
  confirmation: boolean;
  jsPath: string;
  jsExists: boolean;
}

export interface CatalogCommand {
  name: string;
  title: string;
  description: string;
  mode?: string;
}

export interface CatalogExtension {
  extensionName: string;
  extensionTitle: string;
  extensionId: string;
  extensionDir: string;
  enabled: boolean;
  hasAi: boolean;
  aiEvalCount: number;
  aiInstructions: boolean;
  tools: CatalogTool[];
  commands: CatalogCommand[];
}

interface RaybridgeCatalogArgs {
  action?: "summary" | "search" | "detail" | "config" | "doctor" | "recommend";
  query?: string;
  extensionName?: string;
  includeDisabled?: boolean;
  includeCommands?: boolean;
  limit?: number;
}

export function buildRaybridgeToolDef(): ToolDef {
  return {
    name: RAYBRIDGE_TOOL_NAME,
    description: [
      "RayBridge built-in discovery and diagnostics tool.",
      "",
      "Use this before guessing which Raycast extension tool to call. It can summarize installed Raycast AI tools, command-only extensions, active allowlist state, eval coverage, and Raycast API shim gates.",
      "",
      "Actions:",
      "- summary: High-level inventory of installed, enabled, disabled, and command-only extensions.",
      "- search: Search installed extension/tool/command names and descriptions.",
      "- detail: Show one extension's tools, commands, enabled state, and eval coverage.",
      "- config: Show active RayBridge mode, raycastApi gates, and explicitly configured extensions.",
      "- doctor: Diagnose config references, missing tool files, risky enabled tools, and shim gates.",
      "- recommend: Suggest low-risk disabled tools to consider enabling and higher-risk tools to keep disabled.",
    ].join("\n"),
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        action: {
          type: "string",
          enum: ["summary", "search", "detail", "config", "doctor", "recommend"],
          default: "summary",
          description: "Catalog action to run.",
        },
        query: {
          type: "string",
          description: "Search text for action=search.",
        },
        extensionName: {
          type: "string",
          description: "Extension name for action=detail, such as google-calendar.",
        },
        includeDisabled: {
          type: "boolean",
          default: true,
          description: "Include disabled extensions and tools in output.",
        },
        includeCommands: {
          type: "boolean",
          default: true,
          description: "Include Raycast command-only entries. Commands are informational only and are not directly callable as MCP tools.",
        },
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 25,
          description: "Maximum search results.",
        },
      },
    },
  };
}

function normalize(value: unknown): string {
  return typeof value === "string" ? value : "";
}

async function toToolEntry(
  tool: any,
  enabledTools: Set<string>,
  extDir: string
): Promise<CatalogTool> {
  const name = normalize(tool?.name);
  const jsPath = join(extDir, "tools", `${name}.js`);
  const jsExists = Boolean(await stat(jsPath).catch(() => null));

  return {
    name,
    title: normalize(tool?.title) || name,
    description: normalize(tool?.description),
    enabled: enabledTools.has(name),
    confirmation: Boolean(tool?.confirmation),
    jsPath,
    jsExists,
  };
}

function toCommandEntry(command: any): CatalogCommand {
  return {
    name: normalize(command?.name),
    title: normalize(command?.title) || normalize(command?.name),
    description: normalize(command?.description),
    mode: normalize(command?.mode) || undefined,
  };
}

function enabledToolsFor(pkg: any, config: ToolsConfig): Set<string> {
  const extensionName = pkg.name;
  const tools = Array.isArray(pkg.tools) ? pkg.tools : [];
  const allToolNames = tools
    .map((tool: any) => normalize(tool?.name))
    .filter(Boolean);
  const extConfig = config.extensions[extensionName];

  if (config.mode === "blocklist") {
    if (extConfig?.enabled === false) return new Set();
    return extConfig?.tools?.length
      ? new Set(extConfig.tools)
      : new Set(allToolNames);
  }

  if (!extConfig || extConfig.enabled !== true) return new Set();
  return extConfig.tools?.length
    ? new Set(extConfig.tools)
    : new Set(allToolNames);
}

async function readPackageJson(path: string): Promise<any | undefined> {
  try {
    return JSON.parse(await readFile(path, "utf-8"));
  } catch {
    return undefined;
  }
}

async function latestByExtensionName(
  entries: CatalogExtension[],
  extensionsDir: string
): Promise<CatalogExtension[]> {
  const byName = new Map<string, CatalogExtension>();

  for (const entry of entries) {
    const existing = byName.get(entry.extensionName);
    if (!existing) {
      byName.set(entry.extensionName, entry);
      continue;
    }

    const [existingStat, entryStat] = await Promise.all([
      stat(join(extensionsDir, existing.extensionId)).catch(() => null),
      stat(join(extensionsDir, entry.extensionId)).catch(() => null),
    ]);
    if (entryStat && (!existingStat || entryStat.mtimeMs > existingStat.mtimeMs)) {
      byName.set(entry.extensionName, entry);
    }
  }

  return [...byName.values()].sort((a, b) =>
    a.extensionName.localeCompare(b.extensionName)
  );
}

export async function discoverCatalog(config: ToolsConfig): Promise<CatalogExtension[]> {
  const extensionsDir = join(homedir(), ".config", "raycast", "extensions");
  let dirs: string[] = [];
  try {
    dirs = await readdir(extensionsDir);
  } catch {
    return [];
  }

  const entries: CatalogExtension[] = [];
  for (const dirName of dirs) {
    const extDir = join(extensionsDir, dirName);
    const pkg = await readPackageJson(join(extDir, "package.json"));
    if (!pkg?.name) continue;

    const tools = Array.isArray(pkg.tools) ? pkg.tools : [];
    const commands = Array.isArray(pkg.commands) ? pkg.commands : [];
    if (tools.length === 0 && commands.length === 0) continue;

    const enabledToolNames = enabledToolsFor(pkg, config);
    const catalogTools = await Promise.all(
      tools.map((tool: any) => toToolEntry(tool, enabledToolNames, extDir))
    );

    entries.push({
      extensionName: pkg.name,
      extensionTitle: normalize(pkg.title) || pkg.name,
      extensionId: dirName,
      extensionDir: extDir,
      enabled: enabledToolNames.size > 0,
      hasAi: Boolean(pkg.ai) || tools.length > 0,
      aiEvalCount: Array.isArray(pkg.ai?.evals) ? pkg.ai.evals.length : 0,
      aiInstructions: typeof pkg.ai?.instructions === "string",
      tools: catalogTools,
      commands: commands.map(toCommandEntry),
    });
  }

  return latestByExtensionName(entries, extensionsDir);
}

function isLowRiskToolName(name: string): boolean {
  const lowRiskExceptions = new Set([
    "xcode-projects",
    "xcode-swift-package-resolved",
    "xcode-simulators",
    "xcode-simulator-applications",
    "xcode-releases",
  ]);
  return (
    lowRiskExceptions.has(name) ||
    /^(get|list|search|find|read|show|extract|base64-|get-current-)/.test(name)
  );
}

function isHighRiskTool(tool: CatalogTool): boolean {
  return (
    tool.confirmation ||
    /^(delete|remove|trash|kill|killall|close|reopen|merge|run|rerun|cancel|create|update|edit|set|start|stop|pause|continue|boot|shutdown|restart|clear|paste|copy|send|toggle|convert|apply|optimize|resize|pad|flip|crop|launch|add)/.test(tool.name)
  );
}

function formatToolList(tools: CatalogTool[], includeDisabled: boolean): string[] {
  return tools
    .filter((tool) => includeDisabled || tool.enabled)
    .map((tool) => {
      const status = tool.enabled ? "enabled" : "disabled";
      const confirmation = tool.confirmation ? ", confirmation" : "";
      const description = tool.description ? ` - ${tool.description}` : "";
      return `  - ${tool.name} (${status}${confirmation})${description}`;
    });
}

function formatCommandList(commands: CatalogCommand[]): string[] {
  return commands.map((command) => {
    const mode = command.mode ? `, ${command.mode}` : "";
    const description = command.description ? ` - ${command.description}` : "";
    return `  - ${command.name} (command-only${mode})${description}`;
  });
}

function formatSummary(catalog: CatalogExtension[], includeCommands: boolean): string {
  const toolExtensions = catalog.filter((ext) => ext.tools.length > 0);
  const commandOnly = catalog.filter(
    (ext) => ext.tools.length === 0 && ext.commands.length > 0
  );
  const enabled = catalog.filter((ext) => ext.enabled);
  const enabledTools = catalog.reduce(
    (count, ext) => count + ext.tools.filter((tool) => tool.enabled).length,
    0
  );
  const totalTools = catalog.reduce((count, ext) => count + ext.tools.length, 0);
  const evalExtensions = catalog.filter((ext) => ext.aiEvalCount > 0);

  const lines = [
    "# RayBridge Catalog Summary",
    "",
    `- Installed Raycast extensions scanned: ${catalog.length}`,
    `- AI-tool extensions: ${toolExtensions.length}`,
    `- Command-only extensions: ${commandOnly.length}`,
    `- Enabled through RayBridge: ${enabled.length} extensions, ${enabledTools}/${totalTools} tools`,
    `- Extensions with Raycast eval examples: ${evalExtensions.length}`,
    "",
    "## Enabled Extensions",
    ...enabled.map((ext) => `- ${ext.extensionName}: ${ext.tools.filter((tool) => tool.enabled).length}/${ext.tools.length} tools`),
  ];

  if (includeCommands) {
    lines.push(
      "",
      "## Command-Only Extensions",
      "These are informational only; RayBridge cannot call them as structured MCP tools unless the extension adds AI tools.",
      ...commandOnly.map((ext) => `- ${ext.extensionName}: ${ext.commands.length} commands`)
    );
  }

  return lines.join("\n");
}

function searchableText(ext: CatalogExtension): string {
  return [
    ext.extensionName,
    ext.extensionTitle,
    ...ext.tools.flatMap((tool) => [tool.name, tool.title, tool.description]),
    ...ext.commands.flatMap((command) => [command.name, command.title, command.description]),
  ].join(" ").toLowerCase();
}

function formatSearch(
  catalog: CatalogExtension[],
  args: Required<Pick<RaybridgeCatalogArgs, "includeDisabled" | "includeCommands" | "limit">> & { query: string }
): string {
  const query = args.query.trim().toLowerCase();
  const matches = catalog
    .filter((ext) => searchableText(ext).includes(query))
    .filter((ext) => args.includeDisabled || ext.enabled)
    .slice(0, args.limit);

  if (matches.length === 0) {
    return `No Raycast extension, tool, or command matched "${args.query}".`;
  }

  const lines = [`# RayBridge Search: ${args.query}`, ""];
  for (const ext of matches) {
    lines.push(
      `## ${ext.extensionName}`,
      `- ${ext.extensionTitle}`,
      `- RayBridge enabled: ${ext.enabled ? "yes" : "no"}`,
      `- AI eval examples: ${ext.aiEvalCount}`,
      ...formatToolList(ext.tools, args.includeDisabled)
    );
    if (args.includeCommands && ext.commands.length > 0) {
      lines.push("  Commands:", ...formatCommandList(ext.commands));
    }
    lines.push("");
  }

  return lines.join("\n").trim();
}

function formatDetail(
  catalog: CatalogExtension[],
  extensionName: string,
  includeDisabled: boolean,
  includeCommands: boolean
): string {
  const ext = catalog.find((entry) => entry.extensionName === extensionName);
  if (!ext) {
    const names = catalog.map((entry) => entry.extensionName).join(", ");
    return `Unknown Raycast extension "${extensionName}". Installed extensions: ${names}`;
  }

  const lines = [
    `# RayBridge Detail: ${ext.extensionName}`,
    "",
    `- Title: ${ext.extensionTitle}`,
    `- RayBridge enabled: ${ext.enabled ? "yes" : "no"}`,
    `- AI instructions: ${ext.aiInstructions ? "yes" : "no"}`,
    `- AI eval examples: ${ext.aiEvalCount}`,
    `- Tools: ${ext.tools.filter((tool) => tool.enabled).length}/${ext.tools.length} enabled`,
    "",
    "## Tools",
    ...formatToolList(ext.tools, includeDisabled),
  ];

  if (includeCommands) {
    lines.push(
      "",
      "## Commands",
      ext.commands.length > 0
        ? "Command-only entries are informational; they are not directly callable as MCP tools."
        : "No Raycast commands found.",
      ...formatCommandList(ext.commands)
    );
  }

  return lines.join("\n");
}

function formatConfig(config: ToolsConfig): string {
  const configured = Object.entries(config.extensions).sort(([a], [b]) => a.localeCompare(b));
  return [
    "# RayBridge Config",
    "",
    `- Mode: ${config.mode}`,
    `- Configured extensions: ${configured.length}`,
    "- Raycast API gates:",
    ...Object.entries(config.raycastApi ?? {}).map(
      ([key, value]) => `  - ${key}: ${value ? "enabled" : "disabled"}`
    ),
    "",
    "## Extensions",
    ...configured.map(([name, ext]) => {
      const toolCount = ext.tools?.length ? ` (${ext.tools.length} tools)` : "";
      return `- ${name}: ${ext.enabled ? "enabled" : "disabled"}${toolCount}`;
    }),
  ].join("\n");
}

function configuredMissingExtensions(
  catalog: CatalogExtension[],
  config: ToolsConfig
): string[] {
  const installed = new Set(catalog.map((ext) => ext.extensionName));
  return Object.keys(config.extensions).filter((name) => !installed.has(name));
}

function configuredMissingTools(
  catalog: CatalogExtension[],
  config: ToolsConfig
): Array<{ extensionName: string; tools: string[] }> {
  return Object.entries(config.extensions)
    .map(([extensionName, extConfig]) => {
      const ext = catalog.find((entry) => entry.extensionName === extensionName);
      if (!ext || !extConfig.tools?.length) {
        return { extensionName, tools: [] };
      }
      const known = new Set(ext.tools.map((tool) => tool.name));
      return {
        extensionName,
        tools: extConfig.tools.filter((tool) => !known.has(tool)),
      };
    })
    .filter((entry) => entry.tools.length > 0);
}

function formatDoctor(catalog: CatalogExtension[], config: ToolsConfig): string {
  const enabledTools = catalog.flatMap((ext) =>
    ext.tools
      .filter((tool) => tool.enabled)
      .map((tool) => ({ extensionName: ext.extensionName, tool }))
  );
  const enabledRisky = enabledTools.filter(({ tool }) => isHighRiskTool(tool));
  const missingJs = enabledTools.filter(({ tool }) => !tool.jsExists);
  const missingExtensions = configuredMissingExtensions(catalog, config);
  const missingTools = configuredMissingTools(catalog, config);
  const enabledGates = Object.entries(config.raycastApi ?? {})
    .filter(([, value]) => Boolean(value))
    .map(([key]) => key);
  const commandOnly = catalog.filter(
    (ext) => ext.tools.length === 0 && ext.commands.length > 0
  );

  const lines = [
    "# RayBridge Doctor",
    "",
    `- Installed extensions scanned: ${catalog.length}`,
    `- Enabled tools: ${enabledTools.length}`,
    `- Enabled high-risk/confirmation tools: ${enabledRisky.length}`,
    `- Enabled tools missing compiled JS: ${missingJs.length}`,
    `- Configured missing extensions: ${missingExtensions.length}`,
    `- Configured missing tools: ${missingTools.reduce((count, item) => count + item.tools.length, 0)}`,
    `- Command-only extensions: ${commandOnly.length}`,
    `- Enabled Raycast API gates: ${enabledGates.length ? enabledGates.join(", ") : "none"}`,
    "",
    "## Findings",
  ];

  if (missingExtensions.length > 0) {
    lines.push(
      "Configured extensions not installed locally:",
      ...missingExtensions.map((name) => `- ${name}`)
    );
  }

  if (missingTools.length > 0) {
    lines.push(
      "Configured tools not found in installed extension manifests:",
      ...missingTools.map((item) => `- ${item.extensionName}: ${item.tools.join(", ")}`)
    );
  }

  if (missingJs.length > 0) {
    lines.push(
      "Enabled tools with missing compiled JS files:",
      ...missingJs.map(({ extensionName, tool }) => `- ${extensionName}/${tool.name}: ${tool.jsPath}`)
    );
  }

  if (enabledRisky.length > 0) {
    lines.push(
      "Enabled tools that deserve extra care:",
      ...enabledRisky
        .slice(0, 30)
        .map(({ extensionName, tool }) => `- ${extensionName}/${tool.name}${tool.confirmation ? " (confirmation)" : ""}`)
    );
  }

  if (
    missingExtensions.length === 0 &&
    missingTools.length === 0 &&
    missingJs.length === 0
  ) {
    lines.push("- Config references resolve against installed Raycast manifests.");
  }

  lines.push(
    "",
    "## Notes",
    "- Command-only extensions are informational until their Raycast extension adds AI tools.",
    "- `bun run test:shims` loads tools safely; use `bun run test:shims:execute` only for intentional live execution."
  );

  return lines.join("\n");
}

function formatRecommend(
  catalog: CatalogExtension[],
  config: ToolsConfig,
  limit: number
): string {
  const explicitlyDisabled = new Set(
    Object.entries(config.extensions)
      .filter(([, extConfig]) => extConfig.enabled === false)
      .map(([extensionName]) => extensionName)
  );
  const eligible = catalog.filter((ext) => !explicitlyDisabled.has(ext.extensionName));
  const candidates = eligible.flatMap((ext) =>
    ext.tools
      .filter((tool) => !tool.enabled && isLowRiskToolName(tool.name) && !isHighRiskTool(tool))
      .map((tool) => ({ extensionName: ext.extensionName, tool }))
  );
  const risky = eligible.flatMap((ext) =>
    ext.tools
      .filter((tool) => !tool.enabled && isHighRiskTool(tool))
      .map((tool) => ({ extensionName: ext.extensionName, tool }))
  );
  const commandOnly = eligible
    .filter((ext) => ext.tools.length === 0 && ext.commands.length > 0)
    .sort((a, b) => b.commands.length - a.commands.length);

  return [
    "# RayBridge Recommendations",
    "",
    "## Low-Risk Candidates",
    candidates.length > 0
      ? candidates
          .slice(0, limit)
          .map(({ extensionName, tool }) => `- ${extensionName}/${tool.name} - ${tool.description || tool.title}`)
          .join("\n")
      : "- No obvious low-risk disabled tool candidates found.",
    "",
    "## Keep Disabled Unless Needed",
    risky.length > 0
      ? risky
          .slice(0, limit)
          .map(({ extensionName, tool }) => `- ${extensionName}/${tool.name}${tool.confirmation ? " (confirmation)" : ""} - ${tool.description || tool.title}`)
          .join("\n")
      : "- No high-risk disabled tools found.",
    "",
    "## Command-Only Extension Opportunities",
    commandOnly.length > 0
      ? commandOnly
          .slice(0, limit)
          .map((ext) => `- ${ext.extensionName}: ${ext.commands.length} commands. Add Raycast AI tools upstream or locally to expose structured MCP calls.`)
          .join("\n")
      : "- No command-only extensions found.",
    "",
    "## Skipped",
    explicitlyDisabled.size > 0
      ? `Explicitly disabled by config: ${[...explicitlyDisabled].sort().join(", ")}`
      : "No explicitly disabled extensions in config.",
  ].join("\n");
}

export async function runRaybridgeCatalogTool(
  rawArgs: Record<string, unknown>,
  config: ToolsConfig
): Promise<string> {
  const args = rawArgs as RaybridgeCatalogArgs;
  const action = args.action ?? "summary";
  const includeDisabled = args.includeDisabled ?? true;
  const includeCommands = args.includeCommands ?? true;
  const parsedLimit = Number(args.limit ?? 25);
  const limit = Number.isFinite(parsedLimit)
    ? Math.min(Math.max(Math.floor(parsedLimit), 1), 100)
    : 25;
  const catalog = await discoverCatalog(config);

  if (action === "config") return formatConfig(config);
  if (action === "doctor") return formatDoctor(catalog, config);
  if (action === "recommend") return formatRecommend(catalog, config, limit);
  if (action === "detail") {
    return formatDetail(
      catalog,
      args.extensionName || "",
      includeDisabled,
      includeCommands
    );
  }
  if (action === "search") {
    if (!args.query?.trim()) {
      return "Provide a non-empty query for action=search.";
    }
    return formatSearch(catalog, {
      query: args.query,
      includeDisabled,
      includeCommands,
      limit,
    });
  }

  return formatSummary(catalog, includeCommands);
}
