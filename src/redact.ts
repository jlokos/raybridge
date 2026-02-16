function redactJsonValue(msg: string, key: string): string {
  // Matches: "key": "value"   and   "key":"value"
  // Keeps the original key and separator formatting.
  const re = new RegExp(`("${key}"\\s*:\\s*)"(?:\\\\.|[^"\\\\])*"`, "gi");
  return msg.replace(re, `$1"[REDACTED]"`);
}

export function redactSecrets(msg: string): string {
  if (!msg) return msg;

  let out = String(msg);

  // Bearer tokens in headers/log lines.
  out = out.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi, "Bearer [REDACTED]");

  // Common token/key fields (Raycast + generic).
  for (const key of [
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "accessToken",
    "refreshToken",
    "idToken",
    "apiKey",
    "personalAccessToken",
    "MCP_API_KEY",
    "RAYCAST_BACKEND_DB_KEY",
  ]) {
    out = redactJsonValue(out, key);
  }

  // Defense-in-depth: redact obvious URL query params.
  out = out.replace(/([?&](?:access_token|refresh_token|id_token|token)=)[^&#\s]+/gi, "$1[REDACTED]");

  return out;
}

