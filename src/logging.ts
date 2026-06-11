const SENSITIVE_KEY_PATTERN =
  /token|secret|password|authorization|cookie|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|personalAccessToken|clientSecret/i;

const SECRET_TEXT_PATTERNS: Array<[RegExp, string]> = [
  [/((?:authorization)\s*[:=]\s*Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]"],
  [/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]"],
  [/(Basic\s+)[A-Za-z0-9+/=]+/gi, "$1[REDACTED]"],
  [/((?:authorization)\s*[:=]\s*)(?!Bearer\b)[^&\s;]+/gi, "$1[REDACTED]"],
  [/((?:cookie)\s*[:=]\s*)[^&\s;]+/gi, "$1[REDACTED]"],
  [/((?:api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|token|secret|password)=)[^&\s]+/gi, "$1[REDACTED]"],
];

function redactValue(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (depth > 6) return "[MAX_DEPTH]";
  if (!value || typeof value !== "object") {
    return typeof value === "string" ? redactText(value) : value;
  }
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, depth + 1, seen));
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      SENSITIVE_KEY_PATTERN.test(key)
        ? "[REDACTED]"
        : redactValue(entry, depth + 1, seen),
    ])
  );
}

export function redactText(value: string): string {
  return SECRET_TEXT_PATTERNS.reduce(
    (current, [pattern, replacement]) => current.replace(pattern, replacement),
    value
  );
}

export function safeJsonPreview(value: unknown, maxLength = 200): string {
  const json = JSON.stringify(redactValue(value));
  if (!json) return "";
  return json.length > maxLength ? `${json.slice(0, maxLength)}...` : json;
}
