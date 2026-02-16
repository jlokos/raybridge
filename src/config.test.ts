import { describe, expect, it } from "bun:test";
import {
  filterExtensions,
  normalizeLegacyConfig,
  type ToolsConfig,
  type RawToolsConfig,
} from "./config.js";
import type { ExtensionEntry, ToolEntry } from "./discovery.js";

function makeTool(name: string): ToolEntry {
  return {
    name,
    title: name,
    description: "",
    confirmation: false,
    inputSchema: {},
    jsPath: `/fake/${name}.js`,
  };
}

function makeExt(name: string, toolNames: string[]): ExtensionEntry {
  return {
    extensionName: name,
    extensionTitle: name,
    extensionId: name,
    extensionDir: `/fake/${name}`,
    tools: toolNames.map(makeTool),
  };
}

describe("config", () => {
  const extA = makeExt("ext-a", ["t1", "t2", "t3"]);
  const extB = makeExt("ext-b", ["x", "y"]);
  const extensions = [extA, extB];

  describe("filterExtensions", () => {
    it("returns all extensions when config is empty", () => {
      const config: ToolsConfig = { extensions: {} };
      expect(filterExtensions(extensions, config)).toEqual(extensions);
    });

    it("excludes extension with enabled: false", () => {
      const config: ToolsConfig = {
        extensions: { "ext-a": { enabled: false } },
      };
      expect(filterExtensions(extensions, config)).toEqual([extB]);
    });

    it("filters tools by disabledTools", () => {
      const config: ToolsConfig = {
        extensions: {
          "ext-a": { enabled: true, disabledTools: ["t2"] },
        },
      };
      const result = filterExtensions(extensions, config);
      expect(result).toHaveLength(2);
      expect(result[0].tools.map((t) => t.name)).toEqual(["t1", "t3"]);
    });

    it("removes extension when all tools are disabled", () => {
      const config: ToolsConfig = {
        extensions: {
          "ext-a": { enabled: true, disabledTools: ["t1", "t2", "t3"] },
        },
      };
      const result = filterExtensions(extensions, config);
      expect(result).toHaveLength(1);
      expect(result[0].extensionName).toBe("ext-b");
    });

    it("ignores unknown tool names in disabledTools", () => {
      const config: ToolsConfig = {
        extensions: {
          "ext-a": { enabled: true, disabledTools: ["t2", "unknown-tool"] },
        },
      };
      const result = filterExtensions(extensions, config);
      expect(result[0].tools.map((t) => t.name)).toEqual(["t1", "t3"]);
    });
  });

  describe("normalizeLegacyConfig", () => {
    it("passes through blocklist config unchanged", () => {
      const raw: RawToolsConfig = {
        extensions: { "ext-a": { enabled: false } },
      };
      const { config, didMigrate } = normalizeLegacyConfig(raw, extensions);
      expect(didMigrate).toBe(false);
      expect(config.extensions["ext-a"]).toEqual({ enabled: false });
    });

    it("migrates mode allowlist to blocklist", () => {
      const raw: RawToolsConfig = {
        mode: "allowlist",
        extensions: {
          "ext-a": { enabled: true },
          "ext-b": { enabled: false },
        },
      };
      const { config, didMigrate } = normalizeLegacyConfig(raw, extensions);
      expect(didMigrate).toBe(true);
      // ext-a enabled with no disabledTools -> nothing to store (blocklist default)
      expect(config.extensions["ext-a"]).toBeUndefined();
      expect(config.extensions["ext-b"]).toEqual({ enabled: false });
    });

    it("migrates tools allowlist to disabledTools", () => {
      const raw: RawToolsConfig = {
        extensions: {
          "ext-a": { enabled: true, tools: ["t1", "t3"] },
        },
      };
      const { config, didMigrate } = normalizeLegacyConfig(raw, extensions);
      expect(didMigrate).toBe(true);
      expect(config.extensions["ext-a"]).toEqual({
        enabled: true,
        disabledTools: ["t2"],
      });
    });

    it("keeps disabledTools when already present", () => {
      const raw: RawToolsConfig = {
        extensions: {
          "ext-a": { enabled: true, disabledTools: ["t2"] },
        },
      };
      const { config, didMigrate } = normalizeLegacyConfig(raw, extensions);
      expect(didMigrate).toBe(false);
      expect(config.extensions["ext-a"]).toEqual({
        enabled: true,
        disabledTools: ["t2"],
      });
    });

    it("handles empty extensions", () => {
      const raw: RawToolsConfig = { extensions: {} };
      const { config, didMigrate } = normalizeLegacyConfig(raw, extensions);
      expect(didMigrate).toBe(false);
      expect(config.extensions).toEqual({});
    });

    it("handles undefined extensions in raw", () => {
      const raw: RawToolsConfig = {};
      const { config } = normalizeLegacyConfig(raw, extensions);
      expect(config.extensions).toEqual({});
    });

    it("skips extensions not in discovery", () => {
      const raw: RawToolsConfig = {
        extensions: {
          "ext-a": { enabled: false },
          "unknown-ext": { enabled: false },
        },
      };
      const { config } = normalizeLegacyConfig(raw, extensions);
      expect(config.extensions["ext-a"]).toEqual({ enabled: false });
      expect(config.extensions["unknown-ext"]).toBeUndefined();
    });
  });
});
