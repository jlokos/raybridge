#!/usr/bin/env bun

import { executeTool } from "./loader.js";
import { setPreferences, setRaycastTokens, setShimConfig } from "./shims.js";
import type { RaycastApiConfig } from "./config.js";
import type { TokenSet } from "./auth.js";

interface WorkerRequest {
  jsPath: string;
  input: Record<string, unknown>;
  extensionName: string;
  extensionDir: string;
  preferences?: Record<string, Record<string, unknown>>;
  raycastTokens?: Array<[string, TokenSet[]]>;
  shimConfig?: RaycastApiConfig;
}

interface WorkerResponse {
  ok: boolean;
  result?: string;
  error?: string;
}

const RESULT_PREFIX = "__RAYBRIDGE_TOOL_RESULT__:";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf-8");
}

function writeResponse(response: WorkerResponse) {
  const encoded = Buffer.from(JSON.stringify(response), "utf-8").toString("base64");
  process.stdout.write(`${RESULT_PREFIX}${encoded}\n`);
}

async function main() {
  const request = JSON.parse(await readStdin()) as WorkerRequest;

  setShimConfig(request.shimConfig ?? {});
  setPreferences(request.preferences ?? {});
  setRaycastTokens(new Map(request.raycastTokens ?? []));

  try {
    const result = await executeTool(
      request.jsPath,
      request.input ?? {},
      request.extensionName,
      request.extensionDir
    );
    writeResponse({ ok: true, result });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    writeResponse({ ok: false, error: message });
  }
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  writeResponse({ ok: false, error: message });
  process.exitCode = 1;
});
