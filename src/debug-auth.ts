#!/usr/bin/env bun

import { loadRaycastPreferences, loadRaycastTokens } from "./auth.js";
import { getRaycastDataDir, getRaycastExtensionsDir } from "./raycast-paths.js";
import { resolveSqlcipherPath } from "./sqlcipher.js";

async function main() {
  console.log(`platform: ${process.platform} ${process.arch}`);
  console.log(`raycast extensions dir: ${getRaycastExtensionsDir()}`);
  console.log(`raycast data dir: ${getRaycastDataDir()}`);
  try {
    console.log(`db cli: ${await resolveSqlcipherPath()}`);
  } catch (err) {
    console.log(`db cli: unavailable (${String(err)})`);
  }

  const tokens = await loadRaycastTokens();
  console.log(`oauth token sets: ${tokens.size} extension(s)`);

  const prefs = await loadRaycastPreferences();
  console.log(`preferences: ${Object.keys(prefs).length} extension(s)`);

  const tokenExts = Array.from(tokens.keys()).slice(0, 10);
  if (tokenExts.length > 0) {
    console.log(`token extensions (first ${tokenExts.length}): ${tokenExts.join(", ")}`);
  }
}

main().catch((err) => {
  console.error("debug-auth failed:", err);
  process.exit(1);
});
