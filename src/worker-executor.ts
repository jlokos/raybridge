import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { RaycastApiConfig } from "./config.js";
import type { TokenSet } from "./auth.js";

interface ExecuteToolInWorkerArgs {
  jsPath: string;
  input: Record<string, unknown>;
  extensionName: string;
  extensionDir: string;
}

interface ExecutionState {
  preferences: Record<string, Record<string, unknown>>;
  raycastTokens: Map<string, TokenSet[]>;
  shimConfig?: RaycastApiConfig;
}

interface WorkerResponse {
  ok: boolean;
  result?: string;
  error?: string;
}

const RESULT_PREFIX = "__RAYBRIDGE_TOOL_RESULT__:";
const DEFAULT_TIMEOUT_MS = 120_000;

function getWorkerPath(): string {
  return fileURLToPath(new URL("./tool-worker.ts", import.meta.url));
}

function getBunExecutable(): string {
  return process.versions.bun ? process.execPath : process.env.BUN_EXECUTABLE || "bun";
}

function getTimeoutMs(): number {
  const value = Number(process.env.RAYBRIDGE_TOOL_TIMEOUT_MS);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_TIMEOUT_MS;
}

function parseWorkerResponse(stdout: string): WorkerResponse | undefined {
  const line = stdout
    .split(/\r?\n/)
    .reverse()
    .find((candidate) => candidate.startsWith(RESULT_PREFIX));
  if (!line) return undefined;
  const encoded = line.slice(RESULT_PREFIX.length);
  try {
    return JSON.parse(Buffer.from(encoded, "base64").toString("utf-8"));
  } catch {
    return undefined;
  }
}

function preview(value: string): string {
  return value.trim().slice(0, 2000);
}

export async function executeToolInWorker(
  args: ExecuteToolInWorkerArgs,
  state: ExecutionState
): Promise<string> {
  const payload = {
    ...args,
    preferences: state.preferences,
    raycastTokens: [...state.raycastTokens.entries()],
    shimConfig: state.shimConfig ?? {},
  };

  const child = spawn(getBunExecutable(), ["run", getWorkerPath()], {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      RAYBRIDGE_TOOL_WORKER: "1",
    },
  });

  const timeoutMs = getTimeoutMs();
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];

  return await new Promise((resolve, reject) => {
    let settled = false;

    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 500).unref?.();
      reject(
        new Error(
          `Tool worker timed out after ${timeoutMs}ms for ${args.extensionName}/${args.jsPath}`
        )
      );
    }, timeoutMs);
    timeout.unref?.();

    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(err);
    });

    child.on("close", (code) => {
      if (settled) return;
      clearTimeout(timeout);

      const out = Buffer.concat(stdout).toString("utf-8");
      const err = Buffer.concat(stderr).toString("utf-8");
      let response: WorkerResponse | undefined;
      try {
        response = parseWorkerResponse(out);
      } catch (parseErr) {
        settled = true;
        reject(
          new Error(
            `Tool worker returned an invalid result (code ${code}). parseError=${preview(
              String(parseErr)
            )} stdout=${preview(out)} stderr=${preview(err)}`
          )
        );
        return;
      }

      settled = true;

      if (!response) {
        reject(
          new Error(
            `Tool worker exited without a result (code ${code}). stdout=${preview(out)} stderr=${preview(err)}`
          )
        );
        return;
      }

      if (!response.ok) {
        const details = err ? `\nWorker stderr:\n${preview(err)}` : "";
        reject(new Error(`${response.error || "Tool worker failed"}${details}`));
        return;
      }

      resolve(response.result ?? "");
    });

    child.stdin.end(JSON.stringify(payload));
  });
}
