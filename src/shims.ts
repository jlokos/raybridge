import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { EventEmitter } from "node:events";
import type { TokenSet } from "./auth.js";
import type { RaycastApiConfig } from "./config.js";

const require = createRequire(import.meta.url);

let installed = false;
let preferences: Record<string, Record<string, unknown>> = {};

const DEFAULT_SHIM_CONFIG: Required<RaycastApiConfig> = {
  enableLocalStorage: true,
  enableClipboard: false,
  enableSystemActions: false,
  enableDestructiveSystemActions: false,
  enableAppleScript: false,
  enableCommandLaunch: false,
};

let shimConfig: Required<RaycastApiConfig> = { ...DEFAULT_SHIM_CONFIG };

function envFlag(name: string): boolean | undefined {
  const value = process.env[name];
  if (value === undefined) return undefined;
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

export function setShimConfig(config: RaycastApiConfig = {}) {
  shimConfig = {
    ...DEFAULT_SHIM_CONFIG,
    enableLocalStorage:
      envFlag("RAYBRIDGE_ENABLE_LOCAL_STORAGE") ??
      config.enableLocalStorage ??
      DEFAULT_SHIM_CONFIG.enableLocalStorage,
    enableClipboard:
      envFlag("RAYBRIDGE_ENABLE_CLIPBOARD") ??
      config.enableClipboard ??
      DEFAULT_SHIM_CONFIG.enableClipboard,
    enableSystemActions:
      envFlag("RAYBRIDGE_ENABLE_SYSTEM_ACTIONS") ??
      config.enableSystemActions ??
      DEFAULT_SHIM_CONFIG.enableSystemActions,
    enableDestructiveSystemActions:
      envFlag("RAYBRIDGE_ENABLE_DESTRUCTIVE_SYSTEM_ACTIONS") ??
      config.enableDestructiveSystemActions ??
      DEFAULT_SHIM_CONFIG.enableDestructiveSystemActions,
    enableAppleScript:
      envFlag("RAYBRIDGE_ENABLE_APPLESCRIPT") ??
      config.enableAppleScript ??
      DEFAULT_SHIM_CONFIG.enableAppleScript,
    enableCommandLaunch:
      envFlag("RAYBRIDGE_ENABLE_COMMAND_LAUNCH") ??
      config.enableCommandLaunch ??
      DEFAULT_SHIM_CONFIG.enableCommandLaunch,
  };
}

/** Raycast DB OAuth tokens keyed by extension name. */
let raycastTokens = new Map<string, TokenSet[]>();

export function setRaycastTokens(tokens: Map<string, TokenSet[]>) {
  raycastTokens = tokens;
}

export function setPreferences(
  prefs: Record<string, Record<string, unknown>>
) {
  preferences = prefs;
}

/** Current extension context — set before each tool execution. */
let currentExtension = "";
let currentExtensionDir = "";

export function setCurrentExtension(name: string, extensionDir: string) {
  currentExtension = name;
  currentExtensionDir = extensionDir;
}

// ============================================================================
// Auto-stub factory for unknown @raycast/api exports
// ============================================================================

/** Known UI component names that should return () => null */
const UI_COMPONENTS = new Set([
  "List", "Detail", "Form", "Grid", "MenuBarExtra",
  "Action", "ActionPanel", "Icon", "Image", "Color",
  "Keyboard", "Navigation", "EmptyView", "Metadata",
]);

/** Known async function names that should return async () => undefined */
const ASYNC_FUNCTIONS = new Set([
  "showToast", "closeMainWindow", "popToRoot", "open", "showHUD",
  "trash", "showInFinder", "confirmAlert", "getSelectedText",
  "getSelectedFinderItems", "getFrontmostApplication", "launchCommand",
  "updateCommandMetadata", "captureException", "runAppleScript",
]);

/**
 * Creates an auto-stub for any unknown @raycast/api export.
 * The stub behavior depends on the access pattern:
 * - UI components: function returning null with nested component stubs
 * - Async functions: async no-op returning undefined
 * - Enums/constants: Proxy returning the property name as string
 * - Nested namespaces: recursive Proxy
 */
function createAutoStub(name: string): unknown {
  // UI components: return function with nested component stubs
  if (UI_COMPONENTS.has(name) || /^[A-Z]/.test(name)) {
    return createUIComponentStub(name);
  }

  // Known async functions
  if (ASYNC_FUNCTIONS.has(name)) {
    return async () => undefined;
  }

  // Functions starting with lowercase: assume sync function returning undefined
  if (/^[a-z]/.test(name)) {
    return () => undefined;
  }

  // Default: return an enum-like Proxy that returns property names as strings
  return createEnumProxy(name);
}

/**
 * Creates a UI component stub - a function returning null with nested stubs
 * for sub-components (e.g., List.Item, Form.TextField)
 */
function createUIComponentStub(_name: string): unknown {
  const componentFn = () => null;

  return new Proxy(componentFn, {
    get(target, prop) {
      if (prop === "prototype") return target.prototype;
      if (typeof prop === "symbol") return undefined;
      // Sub-components are also UI stubs
      return createUIComponentStub(prop as string);
    },
    apply() {
      return null;
    },
  });
}

/**
 * Creates an enum-like Proxy that returns property names as strings.
 * Handles patterns like Toast.Style.Success -> "Success"
 */
function createEnumProxy(_name: string): unknown {
  return new Proxy({}, {
    get(_, prop) {
      if (typeof prop === "symbol") return undefined;
      // Nested access returns another proxy or the string value
      const value = prop as string;
      // If it looks like an enum value (PascalCase), return the string
      if (/^[A-Z]/.test(value)) {
        return createEnumProxy(value);
      }
      return value;
    },
  });
}

function createStringEnumProxy(): Record<string, string> {
  return new Proxy({}, {
    get(_, prop) {
      if (typeof prop === "symbol") return undefined;
      return prop;
    },
  }) as Record<string, string>;
}

// ============================================================================
// Explicit implementations for critical APIs
// ============================================================================

function safeStorageName(name: string): string {
  return (name || "mcp-bridge").replace(/[^a-zA-Z0-9_.-]/g, "_");
}

async function runCommand(
  command: string,
  args: string[] = [],
  input?: string
): Promise<{ stdout: string; stderr: string }> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];

    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    child.on("error", reject);
    child.on("close", (code) => {
      const out = Buffer.concat(stdout).toString("utf-8");
      const err = Buffer.concat(stderr).toString("utf-8");
      if (code === 0) {
        resolve({ stdout: out, stderr: err });
      } else {
        reject(new Error(`${command} exited with code ${code}: ${err || out}`));
      }
    });

    if (input !== undefined) {
      child.stdin.write(input);
    }
    child.stdin.end();
  });
}

function assertShimEnabled(flag: keyof RaycastApiConfig, apiName: string) {
  if (!shimConfig[flag]) {
    throw new Error(
      `Raycast API ${apiName} is disabled in RayBridge. Enable raycastApi.${flag} in ~/.config/raybridge/tools.json to allow it.`
    );
  }
}

function escapeAppleScriptString(value: string): string {
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error("AppleScript path arguments cannot contain control characters");
  }
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

async function readClipboardText(): Promise<string> {
  assertShimEnabled("enableClipboard", "Clipboard.readText");
  return (await runCommand("pbpaste")).stdout;
}

async function writeClipboardText(value: string): Promise<void> {
  assertShimEnabled("enableClipboard", "Clipboard.copy");
  await runCommand("pbcopy", [], value);
}

/** environment - runtime values for the current extension context */
const environmentDescriptor = {
  get() {
    return {
      launchType: "background",
      commandMode: "no-view",
      commandName: "mcp-bridge",
      extensionName: currentExtension,
      isDevelopment: false,
      assetsPath: currentExtensionDir
        ? join(currentExtensionDir, "assets")
        : "",
      supportPath: join(
        homedir(),
        "Library",
        "Application Support",
        "com.raycast.macos",
        "extensions",
        currentExtension || "mcp-bridge"
      ),
      textSize: "medium",
      theme: "dark",
      appearance: "dark",
      appearanceScheme: "dark",
      raycastVersion: "1.83.0",
      canAccess: () => true,
    };
  },
  enumerable: true,
};

/** Cache - in-memory Map-based cache */
class Cache {
  private store = new Map<string, string>();
  get(key: string) { return this.store.get(key); }
  set(key: string, value: string) { this.store.set(key, value); }
  remove(key: string) { this.store.delete(key); }
  delete(key: string) { this.store.delete(key); }
  has(key: string) { return this.store.has(key); }
  clear() { this.store.clear(); }
  getSession(key: string) { return this.store.get(`session:${key}`); }
  setSession(key: string, value: string) { this.store.set(`session:${key}`, value); }
}

/** OAuth.PKCEClient - token management from Raycast DB */
class PKCEClient {
  constructor(_opts?: { providerName?: string }) {}
  authorizationRequest(opts: {
    endpoint: string;
    clientId: string;
    scope: string;
    extraParameters?: Record<string, string>;
  }) {
    const url = new URL(opts.endpoint);
    url.searchParams.set("client_id", opts.clientId);
    url.searchParams.set("scope", opts.scope);
    url.searchParams.set("response_type", "code");
    url.searchParams.set(
      "redirect_uri",
      "https://raycast.com/redirect?packageName=mcp-bridge"
    );
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("code_challenge", "placeholder");
    if (opts.extraParameters) {
      for (const [k, v] of Object.entries(opts.extraParameters)) {
        url.searchParams.set(k, v);
      }
    }
    return {
      codeChallenge: "placeholder",
      codeVerifier: "placeholder",
      state: "placeholder",
      toURL: () => url.toString(),
    };
  }
  async authorize() {
    return { authorizationCode: "" };
  }
  async getTokens() {
    const extName = currentExtension;
    const dbSets = raycastTokens.get(extName);
    if (dbSets && dbSets.length > 0) {
      const ts = dbSets[0];
      return {
        accessToken: ts.accessToken,
        refreshToken: ts.refreshToken,
        idToken: ts.idToken,
        isExpired: () => {
          if (!ts.expiresIn || !ts.updatedAt) return false;
          const updatedMs = typeof ts.updatedAt === "string"
            ? new Date(ts.updatedAt).getTime()
            : ts.updatedAt;
          return Date.now() > updatedMs + ts.expiresIn * 1000;
        },
      };
    }
    return undefined;
  }
  async setTokens(_response: Record<string, unknown>) {
    // Token persistence handled by Raycast's encrypted DB
  }
  async removeTokens() {
    console.error(`raybridge: removeTokens called for ${currentExtension} (no-op)`);
  }
}

function localStoragePath(): string {
  return join(
    homedir(),
    ".config",
    "raybridge",
    "local-storage",
    `${safeStorageName(currentExtension)}.json`
  );
}

async function readLocalStorage(): Promise<Record<string, unknown>> {
  assertShimEnabled("enableLocalStorage", "LocalStorage");
  try {
    return JSON.parse(await readFile(localStoragePath(), "utf-8"));
  } catch {
    return {};
  }
}

async function writeLocalStorage(values: Record<string, unknown>) {
  assertShimEnabled("enableLocalStorage", "LocalStorage");
  const path = localStoragePath();
  const tempPath = `${path}.${process.pid}.${Date.now()}.tmp`;
  await mkdir(dirname(path), { recursive: true });
  await writeFile(tempPath, JSON.stringify(values, null, 2) + "\n", { mode: 0o600 });
  await rename(tempPath, path);
}

/** LocalStorage - persisted per Raycast extension */
const LocalStorage = {
  getItem: async (key: string) => {
    const values = await readLocalStorage();
    return values[key];
  },
  setItem: async (key: string, value: unknown) => {
    const values = await readLocalStorage();
    values[key] = value;
    await writeLocalStorage(values);
  },
  removeItem: async (key: string) => {
    const values = await readLocalStorage();
    delete values[key];
    await writeLocalStorage(values);
  },
  allItems: async () => readLocalStorage(),
  clear: async () => writeLocalStorage({}),
};

/** getPreferenceValues - reads from preferences map */
function getPreferenceValues<T = Record<string, unknown>>(): T {
  return { ...(preferences[currentExtension] || {}) } as T;
}

/** getApplications - filesystem scan for installed apps */
async function getApplications() {
  const { readdirSync, existsSync } = await import("node:fs");
  const apps: Array<{ name: string; path: string; bundleId?: string }> = [];
  const appDirs = ["/Applications", `${homedir()}/Applications`];
  for (const dir of appDirs) {
    if (!existsSync(dir)) continue;
    try {
      for (const entry of readdirSync(dir)) {
        if (entry.endsWith(".app")) {
          apps.push({
            name: entry.replace(".app", ""),
            path: `${dir}/${entry}`,
            bundleId: undefined,
          });
        }
      }
    } catch {
      // Ignore permission errors
    }
  }
  return apps;
}

function clipboardInputToText(input: unknown): string {
  if (typeof input === "string") return input;
  if (input && typeof input === "object" && "text" in input) {
    const text = (input as { text?: unknown }).text;
    return typeof text === "string" ? text : String(text ?? "");
  }
  return String(input ?? "");
}

async function pasteClipboard() {
  assertShimEnabled("enableAppleScript", "Clipboard.paste");
  await runAppleScript('tell application "System Events" to keystroke "v" using command down');
}

/** Clipboard - macOS clipboard operations gated by config */
const Clipboard = {
  copy: async (text: unknown) => writeClipboardText(clipboardInputToText(text)),
  paste: async () => pasteClipboard(),
  readText: async () => readClipboardText(),
  read: async () => ({ text: await readClipboardText() }),
  clear: async () => writeClipboardText(""),
};

async function open(target: unknown) {
  assertShimEnabled("enableSystemActions", "open");
  const value = target instanceof URL ? target.toString() : String(target ?? "");
  if (!value) throw new Error("Raycast API open requires a target path or URL");
  await runCommand("open", ["--", value]);
}

async function showInFinder(path: unknown) {
  assertShimEnabled("enableSystemActions", "showInFinder");
  const value = String(path ?? "");
  if (!value) throw new Error("Raycast API showInFinder requires a path");
  await runCommand("open", ["-R", "--", value]);
}

async function trash(pathOrPaths: unknown) {
  assertShimEnabled("enableDestructiveSystemActions", "trash");
  const paths = Array.isArray(pathOrPaths) ? pathOrPaths : [pathOrPaths];
  for (const rawPath of paths) {
    const value = String(rawPath ?? "");
    if (!value) continue;
    await runCommand("osascript", [
      "-e",
      `tell application "Finder" to delete POSIX file "${escapeAppleScriptString(value)}"`,
    ]);
  }
}

async function runAppleScript(script: string): Promise<string> {
  assertShimEnabled("enableAppleScript", "runAppleScript");
  return (await runCommand("osascript", ["-e", script])).stdout.trim();
}

async function getSelectedText(): Promise<string> {
  assertShimEnabled("enableAppleScript", "getSelectedText");
  assertShimEnabled("enableClipboard", "getSelectedText");
  const previousClipboard = shimConfig.enableClipboard
    ? await readClipboardText().catch(() => undefined)
    : undefined;

  await runAppleScript('tell application "System Events" to keystroke "c" using command down');
  await new Promise((resolve) => setTimeout(resolve, 120));
  const selected = await readClipboardText();

  if (previousClipboard !== undefined) {
    await writeClipboardText(previousClipboard).catch(() => undefined);
  }

  return selected;
}

async function getSelectedFinderItems(): Promise<Array<{ path: string }>> {
  assertShimEnabled("enableAppleScript", "getSelectedFinderItems");
  const result = await runAppleScript([
    'tell application "Finder"',
    "set selectedItems to selection",
    "set output to \"\"",
    "repeat with itemRef in selectedItems",
    "set output to output & POSIX path of (itemRef as alias) & linefeed",
    "end repeat",
    "return output",
    "end tell",
  ].join("\n"));

  return result
    .split(/\r?\n/)
    .map((path) => path.trim())
    .filter(Boolean)
    .map((path) => ({ path }));
}

async function getFrontmostApplication(): Promise<{ name: string }> {
  assertShimEnabled("enableAppleScript", "getFrontmostApplication");
  const name = await runAppleScript(
    'tell application "System Events" to get name of first application process whose frontmost is true'
  );
  return { name };
}

async function launchCommand(options: unknown) {
  assertShimEnabled("enableCommandLaunch", "launchCommand");
  if (!options || typeof options !== "object") {
    throw new Error("Raycast API launchCommand requires an options object");
  }

  const opts = options as Record<string, unknown>;
  const commandName = typeof opts.name === "string" ? opts.name : "";
  const extensionName =
    typeof opts.extensionName === "string" ? opts.extensionName : currentExtension;
  const owner = typeof opts.ownerOrAuthorName === "string" ? opts.ownerOrAuthorName : "";

  if (!commandName || !extensionName || !owner) {
    throw new Error(
      "Raycast API launchCommand requires name, extensionName/current extension, and ownerOrAuthorName"
    );
  }

  await runCommand("open", ["--", `raycast://extensions/${owner}/${extensionName}/${commandName}`]);
}

type AIAskResult = Promise<string> & EventEmitter;

const AI_MODEL = createStringEnumProxy();

const AI_CREATIVITY = {
  None: "none",
  Low: "low",
  Medium: "medium",
  High: "high",
  Maximum: "maximum",
  none: "none",
  low: "low",
  medium: "medium",
  high: "high",
  maximum: "maximum",
};

function askAI(_prompt: string, _options?: unknown): AIAskResult {
  const emitter = new EventEmitter();
  const resultText = "";
  const promise = Promise.resolve(resultText) as AIAskResult;
  const eventMethods = [
    "addListener",
    "emit",
    "eventNames",
    "getMaxListeners",
    "listenerCount",
    "listeners",
    "off",
    "on",
    "once",
    "prependListener",
    "prependOnceListener",
    "rawListeners",
    "removeAllListeners",
    "removeListener",
    "setMaxListeners",
  ] as const;

  for (const method of eventMethods) {
    (promise as any)[method] = (emitter as any)[method].bind(emitter);
  }

  queueMicrotask(() => {
    if (resultText) emitter.emit("data", resultText);
    emitter.emit("end");
  });

  return promise;
}

/** AI - compatibility stub; RayBridge does not call or route LLMs */
const AI = {
  ask: askAI,
  Model: AI_MODEL,
  model: AI_MODEL,
  Creativity: AI_CREATIVITY,
};

// ============================================================================
// Explicit exports object - these take precedence over auto-stubs
// ============================================================================

const explicitExports: Record<string, unknown> = {
  // Core runtime
  Cache,
  LocalStorage,
  getPreferenceValues,
  getApplications,

  // OAuth namespace
  OAuth: {
    PKCEClient,
    RedirectMethod: { Web: "web", App: "app", AppURI: "app-uri" },
  },

  // Enums with specific values that extensions may check
  LaunchType: { Background: "background", UserInitiated: "userInitiated" },
  PopToRootType: { Default: "default", Suspended: "suspended" },

  // Clipboard and AI with explicit methods
  Clipboard,
  AI,
  open,
  showInFinder,
  trash,
  getSelectedText,
  getSelectedFinderItems,
  getFrontmostApplication,
  launchCommand,
  runAppleScript,

  // Toast with commonly-used Style enum
  Toast: {
    Style: { Success: "success", Failure: "failure", Animated: "animated" },
  },

  // Image with Mask enum
  Image: {
    Mask: { Circle: "circle", RoundedRectangle: "roundedRectangle" },
  },
};

// ============================================================================
// Proxy-based @raycast/api module
// ============================================================================

/**
 * Creates the @raycast/api module with:
 * 1. Explicit implementations for critical APIs
 * 2. Auto-generated stubs for everything else
 */
function createRaycastApiProxy() {
  const handler: ProxyHandler<typeof explicitExports> = {
    get(target, prop) {
      // Handle special properties
      if (prop === "default") return raycastApiProxy;
      if (typeof prop === "symbol") return undefined;

      // Environment is a getter, handle specially
      if (prop === "environment") {
        return environmentDescriptor.get();
      }

      // Return explicit implementation if available
      if (prop in target) {
        return target[prop as string];
      }

      // Auto-stub everything else
      return createAutoStub(prop as string);
    },

    has(_target, _prop) {
      // Everything exists in @raycast/api (via auto-stub)
      return true;
    },

    ownKeys(target) {
      // Return explicit keys for enumeration
      return [...Object.keys(target), "environment", "default"];
    },

    getOwnPropertyDescriptor(target, prop) {
      if (prop === "environment") {
        return { ...environmentDescriptor, configurable: true };
      }
      if (prop === "default") {
        return { value: raycastApiProxy, enumerable: true, configurable: true };
      }
      if (prop in target) {
        return { value: target[prop as string], enumerable: true, configurable: true };
      }
      // Auto-stubbed properties
      return { value: createAutoStub(prop as string), enumerable: true, configurable: true };
    },
  };

  return new Proxy(explicitExports, handler);
}

const raycastApiProxy = createRaycastApiProxy();

// ============================================================================
// Module installation
// ============================================================================

export function installShims() {
  if (installed) return;
  installed = true;

  const shimmedModules: Record<string, unknown> = {
    "@raycast/api": raycastApiProxy,
    react: {
      default: { createElement: () => null, Fragment: "Fragment" },
      createElement: () => null,
      Fragment: "Fragment",
      useState: () => [undefined, () => {}],
      useEffect: () => {},
      useMemo: (fn: () => unknown) => fn(),
      useCallback: (fn: unknown) => fn,
      useRef: () => ({ current: null }),
      useSyncExternalStore: (_subscribe: unknown, getSnapshot: () => unknown) => {
        return typeof getSnapshot === "function" ? getSnapshot() : undefined;
      },
    },
    "react/jsx-runtime": {
      jsx: () => null,
      jsxs: () => null,
      Fragment: "Fragment",
    },
  };

  for (const [name, exports] of Object.entries(shimmedModules)) {
    // For @raycast/api, the proxy handles default export
    const moduleExports = name === "@raycast/api"
      ? exports
      : { ...exports as object, default: exports };

    require.cache[name] = {
      id: name,
      filename: name,
      loaded: true,
      exports: moduleExports,
      children: [],
      paths: [],
      path: "",
      parent: null,
      require,
      isPreloading: false,
    } as any;
  }

  const Module = require("module");
  const origResolve = Module._resolveFilename;
  Module._resolveFilename = function (
    request: string,
    parent: unknown,
    isMain: boolean,
    options: unknown
  ) {
    if (request in shimmedModules) return request;
    return origResolve.call(this, request, parent, isMain, options);
  };
}
