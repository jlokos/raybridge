import type { RaycastAuthData, TokenSet } from "./auth.js";

export interface ExtensionsRow {
  name?: unknown;
  tokenSets?: unknown;
  preferences?: unknown;
}

function safeJsonParse(value: string): any | null {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function normalizeTokenSets(value: string): TokenSet[] | null {
  const parsed = safeJsonParse(value);
  if (!parsed) return null;
  const sets = Array.isArray(parsed) ? parsed : [parsed];
  return sets.length > 0 ? (sets as TokenSet[]) : null;
}

function normalizePreferences(value: string): Record<string, unknown> | null {
  const parsed = safeJsonParse(value);
  if (!Array.isArray(parsed)) return null;
  const out: Record<string, unknown> = {};
  for (const p of parsed) {
    if (!p || typeof p !== "object") continue;
    const name = (p as any).name;
    if (typeof name !== "string" || name.length === 0) continue;
    if (!Object.prototype.hasOwnProperty.call(p, "value")) continue;
    out[name] = (p as any).value;
  }
  return Object.keys(out).length > 0 ? out : null;
}

export function normalizeExtensionsRows(rows: unknown[]): RaycastAuthData {
  const tokens = new Map<string, TokenSet[]>();
  const prefs: Record<string, Record<string, unknown>> = {};

  if (!Array.isArray(rows)) return { tokens, prefs };

  for (const row of rows as ExtensionsRow[]) {
    const name = (row as any)?.name;
    if (typeof name !== "string" || name.length === 0) continue;

    const tokenSets = (row as any)?.tokenSets;
    if (typeof tokenSets === "string" && tokenSets.trim().length > 0) {
      const sets = normalizeTokenSets(tokenSets);
      if (sets) tokens.set(name, sets);
    }

    const preferences = (row as any)?.preferences;
    if (typeof preferences === "string" && preferences.trim().length > 0) {
      const p = normalizePreferences(preferences);
      if (p) prefs[name] = p;
    }
  }

  return { tokens, prefs };
}

export function normalizeBackendDump(parsed: unknown): RaycastAuthData {
  const tokens = new Map<string, TokenSet[]>();
  const prefs: Record<string, Record<string, unknown>> = {};

  if (!parsed || typeof parsed !== "object") return { tokens, prefs };
  const p: any = parsed as any;

  if (p.tokens && typeof p.tokens === "object") {
    for (const [k, v] of Object.entries(p.tokens)) {
      if (!k) continue;
      if (Array.isArray(v)) {
        tokens.set(k, v as TokenSet[]);
      } else if (v && typeof v === "object") {
        // Best-effort: allow a single token set object.
        tokens.set(k, [v as TokenSet]);
      }
    }
  }

  if (p.prefs && typeof p.prefs === "object") {
    for (const [k, v] of Object.entries(p.prefs)) {
      if (!k) continue;
      if (v && typeof v === "object" && !Array.isArray(v)) {
        prefs[k] = v as Record<string, unknown>;
      }
    }
  }

  return { tokens, prefs };
}

