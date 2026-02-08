import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

export interface ToolEntry {
  name: string;
  title: string;
  description: string;
  instructions?: string;
  confirmation: boolean;
  inputSchema: Record<string, unknown>;
  jsPath: string;
}

export interface ExtensionEntry {
  extensionName: string;
  extensionTitle: string;
  extensionId: string;
  extensionDir: string;
  aiInstructions?: string;
  tools: ToolEntry[];
}

export async function discoverExtensions(): Promise<ExtensionEntry[]> {
  const extensionsDir = join(homedir(), ".config", "raycast-x", "extensions");
  const entries: ExtensionEntry[] = [];

  let dirs: string[];
  try {
    dirs = await readdir(extensionsDir);
  } catch {
    console.error(`Cannot read ${extensionsDir}`);
    return [];
  }

  for (const dirName of dirs) {
    const extDir = join(extensionsDir, dirName);
    const pkgPath = join(extDir, "package.json");

    let pkg: any;
    try {
      pkg = JSON.parse(await readFile(pkgPath, "utf-8"));
    } catch {
      continue;
    }

    const tools = pkg.tools;
    if (!Array.isArray(tools) || tools.length === 0) continue;

    const toolEntries: ToolEntry[] = tools.map((t: any) => ({
      name: t.name,
      title: t.title || t.name,
      description: t.description || "",
      instructions: t.instructions,
      confirmation: !!t.confirmation,
      inputSchema: t.input || { type: "object", properties: {} },
      jsPath: join(extDir, "tools", `${t.name}.js`),
    }));

    entries.push({
      extensionName: pkg.name || dirName,
      extensionTitle: pkg.title || pkg.name || dirName,
      extensionId: dirName,
      extensionDir: extDir,
      aiInstructions: pkg.ai?.instructions,
      tools: toolEntries,
    });
  }

  // Deduplicate: keep the newest directory per extension name
  const byName = new Map<string, ExtensionEntry>();
  for (const entry of entries) {
    const existing = byName.get(entry.extensionName);
    if (!existing) {
      byName.set(entry.extensionName, entry);
    } else {
      // Compare directory mtime, keep newer
      const [aStat, bStat] = await Promise.all([
        stat(join(extensionsDir, existing.extensionId)).catch(() => null),
        stat(join(extensionsDir, entry.extensionId)).catch(() => null),
      ]);
      if (bStat && (!aStat || bStat.mtimeMs > aStat.mtimeMs)) {
        byName.set(entry.extensionName, entry);
      }
    }
  }

  return Array.from(byName.values());
}
