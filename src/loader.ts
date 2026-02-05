import { createRequire } from "node:module";
import { installShims, setCurrentExtension } from "./shims.js";

const require = createRequire(import.meta.url);

export async function executeTool(
  jsPath: string,
  input: Record<string, unknown>,
  extensionName: string,
  extensionDir: string
): Promise<string> {
  installShims();
  setCurrentExtension(extensionName, extensionDir);

  delete require.cache[jsPath];

  let mod: any;
  try {
    mod = require(jsPath);
  } catch (err) {
    throw new Error(`Failed to load tool at ${jsPath}: ${err}`);
  }

  const fn = mod.default || mod;
  if (typeof fn !== "function") {
    throw new Error(`Tool at ${jsPath} does not export a function`);
  }

  const result = await fn(input);

  if (typeof result === "string") return result;
  return JSON.stringify(result, null, 2);
}
