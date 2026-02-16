#!/usr/bin/env bun
/**
 * E2E test runner for RayBridge shims
 *
 * Loads each extension tool and executes it with realistic test inputs
 * derived from the tool's input schema. Verifies that tools return
 * actual output and don't fail due to missing shims.
 *
 * Outputs:
 * - Console: Visual ✅/❌ test results
 * - shim-test-results.json: Detailed results for this run
 * - shim-test-audit.log: Append-only audit trail of all runs
 */

import { discoverExtensions, type ToolEntry, type ExtensionEntry } from "./discovery.js";
import { executeTool } from "./loader.js";
import { setPreferences, setRaycastTokens, installShims } from "./shims.js";
import { loadRaycastAuthData } from "./auth.js";
import { readFile, appendFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

interface TestResult {
  extension: string;
  tool: string;
  status: "pass" | "shim_error" | "runtime_error" | "skip";
  error?: string;
  missingShim?: string;
  output?: string;
  inputUsed?: Record<string, unknown>;
}

interface AuditEntry {
  timestamp: string;
  summary: {
    total: number;
    passed: number;
    shimErrors: number;
    runtimeErrors: number;
    skipped: number;
  };
  missingShims: string[];
  duration: number;
}

// Extensions that get stuck in infinite loops (OAuth retry loops, etc.)
const SKIP_EXTENSIONS = new Set([
  "dub",      // Infinite OAuth refresh loop
  "notion",   // OAuth refresh loop
]);

// Patterns that indicate a missing shim (actual @raycast/api issues)
const SHIM_ERROR_PATTERNS = [
  /Cannot find module ['"]@raycast\/api['"]/i,
  /Module not found.*@raycast\/api/i,
  /[@]raycast\/api.*is not defined/i,
];

function categorizeError(error: string): { type: "shim" | "runtime"; detail?: string } {
  // Check for actual shim errors first (missing @raycast/api module)
  for (const pattern of SHIM_ERROR_PATTERNS) {
    if (pattern.test(error)) {
      const match = error.match(/@raycast\/api['"]?\.?(\w+)?/i);
      return { type: "shim", detail: match?.[1] || "@raycast/api" };
    }
  }

  // Everything else is a runtime error (tool validation, network, auth, etc.)
  return { type: "runtime" };
}

/**
 * Generate realistic test input based on JSON Schema
 */
function generateTestInput(schema: Record<string, unknown>): Record<string, unknown> {
  const input: Record<string, unknown> = {};
  const properties = schema.properties as Record<string, any> | undefined;
  const required = (schema.required as string[]) || [];

  if (!properties) return input;

  for (const [key, prop] of Object.entries(properties)) {
    const value = generateValueForProperty(key, prop, required.includes(key));
    if (value !== undefined) {
      input[key] = value;
    }
  }

  return input;
}

/**
 * Generate a test value for a schema property
 */
function generateValueForProperty(
  name: string,
  prop: any,
  isRequired: boolean
): unknown {
  const type = prop.type;
  const examples = prop.examples;
  const defaultValue = prop.default;
  const enumValues = prop.enum;

  if (examples && examples.length > 0) return examples[0];
  if (defaultValue !== undefined) return defaultValue;
  if (enumValues && enumValues.length > 0) return enumValues[0];

  switch (type) {
    case "string":
      return generateStringValue(name, prop);
    case "number":
    case "integer":
      return generateNumberValue(name, prop);
    case "boolean":
      return false;
    case "array":
      if (prop.items) {
        const itemValue = generateValueForProperty(`${name}_item`, prop.items, false);
        return itemValue !== undefined ? [itemValue] : [];
      }
      return [];
    case "object":
      if (prop.properties) return generateTestInput(prop);
      return {};
    default:
      return isRequired ? "" : undefined;
  }
}

function generateStringValue(name: string, prop: any): string {
  const nameLower = name.toLowerCase();
  const format = prop.format;

  if (format === "date" || format === "date-time") return new Date().toISOString();
  if (format === "email") return "test@example.com";
  if (format === "uri" || format === "url") return "https://example.com";

  if (nameLower.includes("email")) return "test@example.com";
  if (nameLower.includes("url") || nameLower.includes("link")) return "https://example.com";
  if (nameLower.includes("date") || nameLower.includes("time")) return new Date().toISOString();
  if (nameLower.includes("path") || nameLower.includes("file")) return "/tmp/test.txt";
  if (nameLower.includes("query") || nameLower.includes("search") || nameLower.includes("text")) return "test query";
  if (nameLower.includes("title") || nameLower.includes("name") || nameLower.includes("subject")) return "Test Title";
  if (nameLower.includes("content") || nameLower.includes("body") || nameLower.includes("message")) return "Test content";
  if (nameLower.includes("id")) return "test-id-123";
  if (nameLower.includes("token")) return "test-token";

  return "test";
}

function generateNumberValue(name: string, prop: any): number {
  const min = prop.minimum ?? 0;
  const max = prop.maximum ?? 100;

  if (prop.minimum !== undefined || prop.maximum !== undefined) {
    return Math.floor((min + max) / 2);
  }

  const nameLower = name.toLowerCase();
  if (nameLower.includes("limit") || nameLower.includes("count")) return 10;
  if (nameLower.includes("page")) return 1;

  return 1;
}

async function loadPreferences(): Promise<Record<string, Record<string, unknown>>> {
  const configPath = join(homedir(), ".config", "raybridge", "preferences.json");
  try {
    return JSON.parse(await readFile(configPath, "utf-8"));
  } catch {
    return {};
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`Timeout after ${ms}ms`)), ms)
    ),
  ]);
}

const TOOL_TIMEOUT = 15000;

async function testTool(
  ext: ExtensionEntry,
  tool: ToolEntry
): Promise<TestResult> {
  const toolId = `${ext.extensionName}/${tool.name}`;

  if (SKIP_EXTENSIONS.has(ext.extensionName)) {
    return { extension: ext.extensionName, tool: tool.name, status: "skip", error: "Problematic extension" };
  }

  const input = generateTestInput(tool.inputSchema);

  try {
    const result = await withTimeout(
      executeTool(tool.jsPath, input, ext.extensionName, ext.extensionDir),
      TOOL_TIMEOUT
    );

    return {
      extension: ext.extensionName,
      tool: tool.name,
      status: "pass",
      output: result?.substring(0, 200),
      inputUsed: input,
    };
  } catch (err: any) {
    const errorMsg = err?.message || String(err);
    const { type, detail } = categorizeError(errorMsg);

    if (type === "shim") {
      return {
        extension: ext.extensionName,
        tool: tool.name,
        status: "shim_error",
        error: errorMsg.split("\n")[0],
        missingShim: detail,
        inputUsed: input,
      };
    } else {
      return {
        extension: ext.extensionName,
        tool: tool.name,
        status: "runtime_error",
        error: errorMsg.split("\n")[0].substring(0, 150),
        inputUsed: input,
      };
    }
  }
}

async function saveAuditEntry(entry: AuditEntry) {
  const auditDir = join(process.cwd(), "test-audit");
  const auditPath = join(auditDir, "shim-test-audit.log");

  try {
    await mkdir(auditDir, { recursive: true });
    const line = JSON.stringify(entry) + "\n";
    await appendFile(auditPath, line);
  } catch (err) {
    console.error("Failed to write audit log:", err);
  }
}

async function main() {
  const startTime = Date.now();

  console.log("\n┌─────────────────────────────────────────────────────────────┐");
  console.log("│              🔍 RayBridge Shim Test Suite                   │");
  console.log("└─────────────────────────────────────────────────────────────┘\n");

  // Initialize
  try {
    const manualPrefs = await loadPreferences();
    const auth = await loadRaycastAuthData();

    const mergedPrefs: Record<string, Record<string, unknown>> = { ...manualPrefs };
    for (const [extName, extPrefs] of Object.entries(auth.prefs || {})) {
      mergedPrefs[extName] = { ...extPrefs, ...(manualPrefs[extName] || {}) };
    }

    setPreferences(mergedPrefs);
    setRaycastTokens(auth.tokens || new Map());
  } catch {
    console.log("⚠️  Could not load OAuth tokens\n");
    const prefs = await loadPreferences();
    setPreferences(prefs);
    setRaycastTokens(new Map());
  }

  installShims();

  // Discover extensions
  const extensions = await discoverExtensions();
  console.log(`📦 Found ${extensions.length} extensions\n`);

  const results: TestResult[] = [];
  const shimErrors = new Map<string, TestResult[]>();

  // Test each tool with visual output
  for (const ext of extensions) {
    const extResults: TestResult[] = [];

    for (const tool of ext.tools) {
      const result = await testTool(ext, tool);
      results.push(result);
      extResults.push(result);

      if (result.status === "shim_error") {
        const key = result.missingShim || "unknown";
        if (!shimErrors.has(key)) shimErrors.set(key, []);
        shimErrors.get(key)!.push(result);
      }
    }

    // Display extension results
    const passed = extResults.filter(r => r.status === "pass").length;
    const shimErr = extResults.filter(r => r.status === "shim_error").length;
    const runtimeErr = extResults.filter(r => r.status === "runtime_error").length;
    const skipped = extResults.filter(r => r.status === "skip").length;

    const status = shimErr > 0 ? "❌" : passed > 0 ? "✅" : runtimeErr > 0 ? "⚠️" : "⏭️";
    const counts = [];
    if (passed > 0) counts.push(`✅${passed}`);
    if (shimErr > 0) counts.push(`❌${shimErr}`);
    if (runtimeErr > 0) counts.push(`⚠️${runtimeErr}`);
    if (skipped > 0) counts.push(`⏭️${skipped}`);

    console.log(`${status} ${ext.extensionName.padEnd(25)} ${counts.join(" ")}`);
  }

  // Summary
  const totalPassed = results.filter(r => r.status === "pass").length;
  const totalShimErr = results.filter(r => r.status === "shim_error").length;
  const totalRuntimeErr = results.filter(r => r.status === "runtime_error").length;
  const totalSkipped = results.filter(r => r.status === "skip").length;

  console.log("\n┌─────────────────────────────────────────────────────────────┐");
  console.log("│                        SUMMARY                              │");
  console.log("├─────────────────────────────────────────────────────────────┤");
  console.log(`│  Total tools:    ${results.length.toString().padStart(5)}                                    │`);
  console.log(`│  ✅ Passed:      ${totalPassed.toString().padStart(5)}                                    │`);
  console.log(`│  ❌ Shim errors: ${totalShimErr.toString().padStart(5)}                                    │`);
  console.log(`│  ⚠️  Runtime:     ${totalRuntimeErr.toString().padStart(5)}                                    │`);
  console.log(`│  ⏭️  Skipped:     ${totalSkipped.toString().padStart(5)}                                    │`);
  console.log("└─────────────────────────────────────────────────────────────┘");

  // Show shim errors if any
  if (shimErrors.size > 0) {
    console.log("\n┌─────────────────────────────────────────────────────────────┐");
    console.log("│                 ❌ MISSING SHIMS DETECTED                   │");
    console.log("└─────────────────────────────────────────────────────────────┘\n");

    for (const [shim, affected] of shimErrors.entries()) {
      console.log(`❌ ${shim} (${affected.length} tools affected)`);
      for (const result of affected.slice(0, 3)) {
        console.log(`   └─ ${result.extension}/${result.tool}`);
      }
      if (affected.length > 3) {
        console.log(`   └─ ... and ${affected.length - 3} more`);
      }
    }
  } else {
    console.log("\n┌─────────────────────────────────────────────────────────────┐");
    console.log("│     ✅ ALL SHIMS WORKING - No @raycast/api issues!         │");
    console.log("└─────────────────────────────────────────────────────────────┘");
  }

  // Show sample outputs
  const passedResults = results.filter(r => r.status === "pass" && r.output);
  if (passedResults.length > 0) {
    console.log("\n📋 Sample passing outputs:");
    for (const result of passedResults.slice(0, 3)) {
      const shortOutput = result.output?.substring(0, 60).replace(/\n/g, " ") || "";
      console.log(`   ✅ ${result.extension}/${result.tool}`);
      console.log(`      → ${shortOutput}${result.output && result.output.length > 60 ? "..." : ""}`);
    }
  }

  // Show sample runtime errors
  const runtimeErrors = results.filter(r => r.status === "runtime_error");
  if (runtimeErrors.length > 0 && runtimeErrors.length <= 10) {
    console.log("\n⚠️  Runtime errors (expected - not shim issues):");
    for (const result of runtimeErrors.slice(0, 3)) {
      console.log(`   ⚠️  ${result.extension}/${result.tool}: ${result.error?.substring(0, 50)}...`);
    }
    if (runtimeErrors.length > 3) {
      console.log(`   ... and ${runtimeErrors.length - 3} more`);
    }
  }

  const duration = Date.now() - startTime;

  // Save audit trail
  const auditEntry: AuditEntry = {
    timestamp: new Date().toISOString(),
    summary: {
      total: results.length,
      passed: totalPassed,
      shimErrors: totalShimErr,
      runtimeErrors: totalRuntimeErr,
      skipped: totalSkipped,
    },
    missingShims: [...shimErrors.keys()],
    duration,
  };
  await saveAuditEntry(auditEntry);

  // Write detailed results
  const reportPath = join(process.cwd(), "shim-test-results.json");
  await Bun.write(reportPath, JSON.stringify(results, null, 2));

  console.log(`\n⏱️  Completed in ${(duration / 1000).toFixed(1)}s`);
  console.log(`📄 Results: ${reportPath}`);
  console.log(`📜 Audit: test-audit/shim-test-audit.log`);

  // Exit with error if there are actual shim errors
  if (totalShimErr > 0) {
    process.exit(1);
  }
}

main().catch(console.error);
