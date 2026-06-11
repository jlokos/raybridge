#!/usr/bin/env bun

import { normalizeToolsConfig } from "./config.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function main() {
  const invalid = normalizeToolsConfig({
    mode: "enable-everything",
    raycastApi: {
      enableClipboard: "yes",
      enableSystemActions: true,
    },
    extensions: {
      github: {
        enabled: "true",
        tools: ["search-issues", "", "search-issues", 42],
      },
      slack: null,
    },
  });

  assert(invalid.mode === "allowlist", "Invalid mode should fall back to allowlist");
  assert(invalid.raycastApi?.enableClipboard === false, "Non-boolean shim gate should use safe default");
  assert(invalid.raycastApi?.enableSystemActions === true, "Boolean shim gate should be preserved");
  assert(invalid.extensions.github.enabled === false, "Invalid allowlist extension enabled value should be false");
  assert(
    invalid.extensions.github.tools?.join(",") === "search-issues",
    "Tool lists should be string-only and deduplicated"
  );
  assert(!("slack" in invalid.extensions), "Malformed extension entries should be ignored");

  const blocklist = normalizeToolsConfig({
    mode: "blocklist",
    extensions: {
      arc: {
        enabled: "true",
        tools: ["get-tabs"],
      },
    },
  });

  assert(blocklist.mode === "blocklist", "Valid blocklist mode should be preserved");
  assert(blocklist.extensions.arc.enabled === true, "Blocklist extension entries default to enabled");
  assert(blocklist.extensions.arc.tools?.[0] === "get-tabs", "Blocklist tool filter should be preserved");

  console.log("Config normalization test passed");
}

main();
