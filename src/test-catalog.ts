#!/usr/bin/env bun

import { discoverCatalog, runRaybridgeCatalogTool } from "./catalog.js";
import { loadToolsConfig, normalizeToolsConfig } from "./config.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

async function main() {
  const config = await loadToolsConfig();
  const catalog = await discoverCatalog(config);
  if (catalog.length === 0) {
    console.log("Skipped: no Raycast extensions discovered");
    return;
  }

  const summary = await runRaybridgeCatalogTool({ action: "summary" }, config);
  assert(summary.includes("RayBridge Catalog Summary"), "Summary header missing");
  assert(summary.includes("Enabled through RayBridge"), "Enabled-count summary missing");

  const target =
    catalog.find((extension) => extension.extensionName === "google-calendar") ??
    catalog.find((extension) => extension.tools.length > 0) ??
    catalog[0];
  assert(target, "Expected at least one catalog target");

  const search = await runRaybridgeCatalogTool(
    { action: "search", query: target.extensionName, limit: 10 },
    config
  );
  assert(search.includes(target.extensionName), `Search should find ${target.extensionName}`);

  const detail = await runRaybridgeCatalogTool(
    { action: "detail", extensionName: target.extensionName },
    config
  );
  assert(detail.includes(`RayBridge Detail: ${target.extensionName}`), "Detail header missing");
  if (target.commands.length > 0) {
    assert(detail.includes("Command-only entries"), "Detail should explain command-only entries");
  }

  const configOutput = await runRaybridgeCatalogTool({ action: "config" }, config);
  assert(configOutput.includes("Raycast API gates"), "Config should list shim gates");

  const doctor = await runRaybridgeCatalogTool({ action: "doctor" }, config);
  assert(doctor.includes("RayBridge Doctor"), "Doctor header missing");
  assert(doctor.includes("Configured missing extensions"), "Doctor should report missing config references");

  const recommend = await runRaybridgeCatalogTool({ action: "recommend", limit: 5 }, config);
  assert(recommend.includes("RayBridge Recommendations"), "Recommendations header missing");
  assert(recommend.includes("Low-Risk Candidates"), "Recommendations should list low-risk candidates");

  const disabledConfig = normalizeToolsConfig({
    mode: "allowlist",
    extensions: {
      ccusage: { enabled: false },
    },
  });
  const disabledRecommend = await runRaybridgeCatalogTool(
    { action: "recommend", limit: 5 },
    disabledConfig
  );
  assert(
    !disabledRecommend.includes("ccusage/get-"),
    "Recommendations should respect explicitly disabled extensions"
  );

  console.log("Catalog test passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
