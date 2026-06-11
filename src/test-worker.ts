#!/usr/bin/env bun

import { discoverExtensions } from "./discovery.js";
import { executeToolInWorker } from "./worker-executor.js";
import { loadToolsConfig } from "./config.js";
import { fileURLToPath } from "node:url";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

async function main() {
  const [extensions, config] = await Promise.all([
    discoverExtensions(),
    loadToolsConfig(),
  ]);

  const base64 = extensions.find((ext) => ext.extensionName === "base64");
  const tool = base64?.tools.find((entry) => entry.name === "base64-encode");
  if (!base64 || !tool) {
    console.warn("Skipped base64 worker smoke test: base64/base64-encode is not installed");
  } else {
    const result = await executeToolInWorker(
      {
        jsPath: tool.jsPath,
        input: { input: "worker isolation works" },
        extensionName: base64.extensionName,
        extensionDir: base64.extensionDir,
      },
      {
        preferences: {},
        raycastTokens: new Map(),
        shimConfig: config.raycastApi,
      }
    );

    assert(
      result === "d29ya2VyIGlzb2xhdGlvbiB3b3Jrcw==",
      `Unexpected worker result: ${result}`
    );
  }

  const errorFixture = fileURLToPath(
    new URL("./test-fixtures/worker-error-tool.cjs", import.meta.url)
  );
  try {
    await executeToolInWorker(
      {
        jsPath: errorFixture,
        input: {},
        extensionName: "worker-fixture",
        extensionDir: "",
      },
      {
        preferences: {},
        raycastTokens: new Map(),
        shimConfig: config.raycastApi,
      }
    );
    throw new Error("Expected worker fixture to throw");
  } catch (err: unknown) {
    assert(
      String(err instanceof Error ? err.message : err).includes("fixture failure"),
      `Unexpected worker error: ${err}`
    );
  }

  const timeoutFixture = fileURLToPath(
    new URL("./test-fixtures/worker-timeout-tool.cjs", import.meta.url)
  );
  const previousTimeout = process.env.RAYBRIDGE_TOOL_TIMEOUT_MS;
  process.env.RAYBRIDGE_TOOL_TIMEOUT_MS = "50";
  try {
    try {
      await executeToolInWorker(
        {
          jsPath: timeoutFixture,
          input: {},
          extensionName: "worker-fixture",
          extensionDir: "",
        },
        {
          preferences: {},
          raycastTokens: new Map(),
          shimConfig: config.raycastApi,
        }
      );
      throw new Error("Expected worker fixture to time out");
    } catch (err: unknown) {
      assert(
        String(err instanceof Error ? err.message : err).includes("timed out"),
        `Unexpected timeout error: ${err}`
      );
    }
  } finally {
    if (previousTimeout === undefined) {
      delete process.env.RAYBRIDGE_TOOL_TIMEOUT_MS;
    } else {
      process.env.RAYBRIDGE_TOOL_TIMEOUT_MS = previousTimeout;
    }
  }

  console.log("Worker execution test passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
