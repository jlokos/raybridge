#!/usr/bin/env bun

import { createRequire } from "node:module";
import {
  installShims,
  setCurrentExtension,
  setShimConfig,
} from "./shims.js";

const require = createRequire(import.meta.url);

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function assertRejects(fn: () => Promise<unknown>, message: string) {
  try {
    await fn();
  } catch {
    return;
  }
  throw new Error(message);
}

async function main() {
  setCurrentExtension("raybridge-shim-gate-test", "");
  setShimConfig({
    enableLocalStorage: true,
    enableClipboard: false,
    enableSystemActions: false,
    enableDestructiveSystemActions: false,
    enableAppleScript: false,
    enableCommandLaunch: false,
  });
  installShims();

  const raycast = require("@raycast/api");
  await raycast.LocalStorage.setItem("probe", "ok");
  assert(await raycast.LocalStorage.getItem("probe") === "ok", "LocalStorage get/set failed");
  await raycast.LocalStorage.clear();

  await assertRejects(
    () => raycast.Clipboard.readText(),
    "Clipboard should be disabled by raycastApi gate"
  );
  await assertRejects(
    () => raycast.open("https://example.com"),
    "open should be disabled by raycastApi gate"
  );
  await assertRejects(
    () => raycast.runAppleScript("return 1"),
    "AppleScript should be disabled by raycastApi gate"
  );

  assert(raycast.environment.canAccess(raycast.AI), "environment.canAccess(AI) should be true");
  assert(
    raycast.AI.Model["OpenAI_GPT-4o_mini"] === "OpenAI_GPT-4o_mini",
    "AI.Model should expose string enum values"
  );
  assert(
    raycast.AI.Creativity.High === "high",
    "AI.Creativity should expose documented creativity values"
  );

  const answer = raycast.AI.ask("Suggest 5 jazz songs");
  let streamEnded = false;
  assert(typeof answer.on === "function", "AI.ask should return an EventEmitter-compatible promise");
  answer.on("data", (chunk: string) => {
    assert(typeof chunk === "string", "AI.ask data chunks should be strings");
  });
  answer.on("end", () => {
    streamEnded = true;
  });
  assert(await answer === "", "AI.ask compatibility stub should resolve to an empty string");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert(streamEnded, "AI.ask should emit an end event");

  console.log("Shim gate test passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
