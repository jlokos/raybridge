import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { discoverExtensions, type ExtensionEntry } from "./discovery.js";
import { executeTool } from "./loader.js";
import { setPreferences, setRaycastTokens } from "./shims.js";
import { loadRaycastTokens, loadRaycastPreferences } from "./auth.js";
import { loadToolsConfig, filterExtensions } from "./config.js";
import { startExtensionWatcher } from "./watcher.js";
import { redactSecrets } from "./redact.js";

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface ServerContext {
  extensions: ExtensionEntry[];
  tools: ToolDef[];
  lookup: Map<string, { ext: ExtensionEntry; toolIndex: number }>;
}

async function loadPreferences(): Promise<
  Record<string, Record<string, unknown>>
> {
  const configPath = join(
    homedir(),
    ".config",
    "raybridge",
    "preferences.json"
  );
  try {
    return JSON.parse(await readFile(configPath, "utf-8"));
  } catch {
    return {};
  }
}

export function buildToolDefs(extensions: ExtensionEntry[]): {
  tools: ToolDef[];
  lookup: Map<string, { ext: ExtensionEntry; toolIndex: number }>;
} {
  const tools: ToolDef[] = [];
  const lookup = new Map<string, { ext: ExtensionEntry; toolIndex: number }>();

  for (const ext of extensions) {
    // Build tool catalog with full instructions
    const toolCatalog = ext.tools
      .map((t) => {
        let entry = `### ${t.name}\n${t.description}`;
        if (t.instructions) {
          entry += `\n${t.instructions}`;
        }
        if (t.confirmation) {
          entry += `\n⚠️ This tool performs a destructive/important action. Confirm with the user before calling.`;
        }
        const props = (t.inputSchema as any)?.properties;
        if (props) {
          const paramLines = Object.entries(props)
            .map(([k, v]: [string, any]) => {
              const req = (t.inputSchema as any)?.required?.includes(k)
                ? " (required)"
                : "";
              return `  - ${k}: ${v.type || "string"}${req} — ${v.description || ""}`;
            })
            .join("\n");
          entry += `\nParameters:\n${paramLines}`;
        }
        return entry;
      })
      .join("\n\n");

    let description = `${ext.extensionTitle} extension tools.\n\n${toolCatalog}`;
    if (ext.aiInstructions) {
      description += `\n\n---\nExtension instructions:\n${ext.aiInstructions}`;
    }

    // Build a combined JSON Schema with tool_name enum + input object
    const toolNameEnum = ext.tools.map((t) => t.name);

    // Build a JSON Schema "oneOf" or keep it simple with tool_name + input
    const inputSchema: Record<string, unknown> = {
      type: "object",
      properties: {
        tool_name: {
          type: "string",
          enum: toolNameEnum,
          description: "Which tool to run",
        },
        input: {
          type: "object",
          description:
            "Input parameters for the selected tool (see tool descriptions for schema)",
          additionalProperties: true,
        },
      },
      required: ["tool_name"],
    };

    tools.push({
      name: ext.extensionName,
      description,
      inputSchema,
    });

    for (let i = 0; i < ext.tools.length; i++) {
      lookup.set(`${ext.extensionName}:${ext.tools[i].name}`, {
        ext,
        toolIndex: i,
      });
    }
  }

  return { tools, lookup };
}

export function createMcpServer(ctx: ServerContext): Server {
  // Note: handlers reference ctx directly to support dynamic reloading
  const server = new Server(
    { name: "raycast-tools", version: "1.0.0" },
    { capabilities: { tools: { listChanged: true } } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: ctx.tools,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const extName = request.params.name;
    const args = (request.params.arguments || {}) as {
      tool_name?: string;
      input?: Record<string, unknown>;
    };

    if (!args.tool_name) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Missing required parameter "tool_name". Available extensions: ${ctx.extensions.map((e) => e.extensionName).join(", ")}`,
          },
        ],
        isError: true,
      };
    }

    const entry = ctx.lookup.get(`${extName}:${args.tool_name}`);
    if (!entry) {
      // Find the extension to list available tools
      const ext = ctx.extensions.find((e) => e.extensionName === extName);
      const available = ext
        ? ext.tools.map((t) => t.name).join(", ")
        : `Unknown extension "${extName}"`;
      return {
        content: [
          {
            type: "text" as const,
            text: `Unknown tool "${args.tool_name}". Available: ${available}`,
          },
        ],
        isError: true,
      };
    }

    const tool = entry.ext.tools[entry.toolIndex];
    const inputSummary = redactSecrets(JSON.stringify(args.input || {}).slice(0, 200));
    const startTime = Date.now();

    console.error(`raybridge: [CALL] ${extName}/${args.tool_name} input=${inputSummary}`);

    try {
      const result = await executeTool(
        tool.jsPath,
        args.input || {},
        entry.ext.extensionName,
        entry.ext.extensionDir
      );
      const duration = Date.now() - startTime;
      // Never log tool outputs (they may contain OAuth tokens or other secrets).
      console.error(`raybridge: [OK] ${extName}/${args.tool_name} (${duration}ms)`);
      return { content: [{ type: "text" as const, text: result }] };
    } catch (err: any) {
      const duration = Date.now() - startTime;
      const msg = redactSecrets(err?.message || String(err));
      console.error(
        `raybridge: [ERR] ${extName}/${args.tool_name} (${duration}ms) error=${msg.slice(0, 150)}`
      );
      const isAuthError =
        /token|oauth|unauthorized|403|401|invalid_grant|Missing required parameter: code/i.test(msg);
      const text = isAuthError
        ? `OAuth error for ${extName}/${args.tool_name}: ${msg}\n\nThis extension requires OAuth authentication managed by Raycast. The tokens are stored in Raycast's encrypted database and cannot be accessed externally.\n\nWorkaround: If this extension supports personal access tokens, add them to ${join(homedir(), ".config", "raybridge", "preferences.json")}:\n{\n  "${extName}": { "personalAccessToken": "your-token-here" }\n}`
        : `Error: ${msg}`;
      return {
        content: [{ type: "text" as const, text }],
        isError: true,
      };
    }
  });

  return server;
}

function parseArgs(): { http: boolean; port: number; host: string } {
  const args = process.argv.slice(2);
  let http = process.env.MCP_HTTP === "true";
  let port = parseInt(process.env.MCP_PORT || "3000", 10);
  // Secure-by-default: bind only to loopback unless the user explicitly opts into remote exposure.
  let host = process.env.MCP_HOST || "127.0.0.1";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--http") {
      http = true;
    } else if (args[i] === "--port" && args[i + 1]) {
      port = parseInt(args[i + 1], 10);
      i++;
    } else if (args[i].startsWith("--port=")) {
      port = parseInt(args[i].split("=")[1], 10);
    } else if (args[i] === "--host" && args[i + 1]) {
      host = args[i + 1];
      i++;
    } else if (args[i].startsWith("--host=")) {
      host = args[i].split("=")[1];
    }
  }

  return { http, port, host };
}

export async function loadServerContext(): Promise<ServerContext> {
  const [localExtensions, manualPrefs, toolsConfig] = await Promise.all([
    discoverExtensions(),
    loadPreferences(),
    loadToolsConfig(),
  ]);

  // Load preferences from Raycast's encrypted database and merge with manual prefs
  // Manual prefs override Raycast prefs
  let mergedPrefs = { ...manualPrefs };
  try {
    const raycastPrefs = await loadRaycastPreferences();
    for (const [extName, extPrefs] of Object.entries(raycastPrefs)) {
      mergedPrefs[extName] = { ...extPrefs, ...(manualPrefs[extName] || {}) };
    }
    const prefsCount = Object.keys(raycastPrefs).length;
    if (prefsCount > 0) {
      console.error(
        `raybridge: Loaded preferences for ${prefsCount} extensions from Raycast DB`
      );
    }
  } catch (err: any) {
    console.error(`raybridge: Could not load Raycast preferences: ${err.message}`);
  }
  setPreferences(mergedPrefs);

  // Load OAuth tokens from Raycast's encrypted database
  try {
    const raycastTokens = await loadRaycastTokens();
    setRaycastTokens(raycastTokens);
    console.error(
      `raybridge: Loaded OAuth tokens for ${raycastTokens.size} extensions`
    );
  } catch (err: any) {
    console.error(`raybridge: Could not load OAuth tokens: ${err.message}`);
  }

  const extensions = filterExtensions(localExtensions, toolsConfig);

  if (extensions.length < localExtensions.length) {
    const disabled = localExtensions.length - extensions.length;
    console.error(`raybridge: ${disabled} extension(s) disabled by config`);
  }

  const { tools, lookup } = buildToolDefs(extensions);

  const toolCount = extensions.reduce((n, e) => n + e.tools.length, 0);
  console.error(
    `raybridge: Registered ${extensions.length} extensions (${toolCount} tools total)`
  );

  return { extensions, tools, lookup };
}

/**
 * Reload tools, preferences, OAuth tokens, and update the context in place.
 * Returns true if tools changed.
 */
export async function reloadServerContext(ctx: ServerContext): Promise<boolean> {
  const [localExtensions, manualPrefs, toolsConfig] = await Promise.all([
    discoverExtensions(),
    loadPreferences(),
    loadToolsConfig(),
  ]);

  // Reload preferences from Raycast DB
  let mergedPrefs = { ...manualPrefs };
  try {
    const raycastPrefs = await loadRaycastPreferences();
    for (const [extName, extPrefs] of Object.entries(raycastPrefs)) {
      mergedPrefs[extName] = { ...extPrefs, ...(manualPrefs[extName] || {}) };
    }
    const prefsCount = Object.keys(raycastPrefs).length;
    if (prefsCount > 0) {
      console.error(
        `raybridge: Reloaded preferences for ${prefsCount} extensions`
      );
    }
  } catch (err: any) {
    console.error(`raybridge: Could not reload Raycast preferences: ${err.message}`);
  }
  setPreferences(mergedPrefs);

  // Reload OAuth tokens from Raycast DB
  try {
    const raycastTokens = await loadRaycastTokens();
    setRaycastTokens(raycastTokens);
    console.error(
      `raybridge: Reloaded OAuth tokens for ${raycastTokens.size} extensions`
    );
  } catch (err: any) {
    console.error(`raybridge: Could not reload OAuth tokens: ${err.message}`);
  }

  const extensions = filterExtensions(localExtensions, toolsConfig);
  const { tools, lookup } = buildToolDefs(extensions);

  // Check if tools changed
  const oldToolNames = ctx.tools.map((t) => t.name).sort().join(",");
  const newToolNames = tools.map((t) => t.name).sort().join(",");

  if (oldToolNames === newToolNames) {
    // No change in tool list (but prefs/tokens still reloaded)
    return false;
  }

  // Update context in place
  ctx.extensions = extensions;
  ctx.tools = tools;
  ctx.lookup = lookup;

  const toolCount = extensions.reduce((n, e) => n + e.tools.length, 0);
  console.error(
    `raybridge: Reloaded ${extensions.length} extensions (${toolCount} tools total)`
  );

  return true;
}

async function main() {
  const { http, port, host } = parseArgs();
  const apiKey = process.env.MCP_API_KEY;

  const ctx = await loadServerContext();
  const servers: Server[] = [];

  if (http) {
    const isLoopback =
      host === "127.0.0.1" ||
      host === "localhost" ||
      host === "::1";
    if (!isLoopback) {
      console.error("raybridge: WARNING: HTTP is bound to a non-loopback interface.");
      console.error("raybridge: WARNING: This may expose Raycast OAuth tokens to other machines/users.");
      console.error("raybridge: WARNING: Prefer --host 127.0.0.1 and use firewall rules if needed.");
    }

    // HTTP mode
    const { startHttpServer } = await import("./http-server.js");

    // Start watcher with callback to get servers from http-server
    startExtensionWatcher({
      onReload: () => reloadServerContext(ctx),
      getServers: () => servers,
    });

    await startHttpServer({
      port,
      host,
      apiKey,
      ctx,
      onServerCreated: (server) => servers.push(server),
      onServerClosed: (server) => {
        const idx = servers.indexOf(server);
        if (idx >= 0) servers.splice(idx, 1);
      },
    });
  } else {
    // Stdio mode (default)
    const server = createMcpServer(ctx);
    servers.push(server);

    // Start watcher for dynamic reloading
    startExtensionWatcher({
      onReload: () => reloadServerContext(ctx),
      getServers: () => servers,
    });

    const transport = new StdioServerTransport();
    await server.connect(transport);
  }
}

main().catch((err) => {
  console.error("Fatal:", redactSecrets(String(err)));
  process.exit(1);
});
