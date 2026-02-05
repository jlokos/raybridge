import { createRequire } from "node:module";
import { join } from "node:path";
import { homedir } from "node:os";
import type { TokenSet } from "./auth.js";

const require = createRequire(import.meta.url);

let installed = false;
let preferences: Record<string, Record<string, unknown>> = {};

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

// ============================================================================
// Explicit implementations for critical APIs
// ============================================================================

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
    console.error(`ray-ai-tools: removeTokens called for ${currentExtension} (no-op)`);
  }
}

/** LocalStorage - async stubs */
const LocalStorage = {
  getItem: async (_key: string) => undefined,
  setItem: async (_key: string, _value: string) => {},
  removeItem: async (_key: string) => {},
  allItems: async () => ({}),
  clear: async () => {},
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

/** Clipboard - clipboard operations */
const Clipboard = {
  copy: async (_text: string) => {},
  paste: async () => {},
  readText: async () => "",
  read: async () => ({ text: "" }),
  clear: async () => {},
};

/** AI - AI operations stub */
const AI = {
  ask: async () => "",
  model: createEnumProxy("model"),
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
