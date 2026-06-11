#!/usr/bin/env bun

import { redactText, safeJsonPreview } from "./logging.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function main() {
  const preview = safeJsonPreview({
    query: "hello",
    personalAccessToken: "ghp_secret",
    nested: {
      api_key: "abc123",
      url: "https://example.com/?token=abc123&ok=true",
    },
  });

  assert(preview.includes("hello"), "Non-sensitive values should remain visible");
  assert(preview.includes("[REDACTED]"), "Sensitive values should be redacted");
  assert(!preview.includes("ghp_secret"), "Personal access tokens should not appear");
  assert(!preview.includes("abc123"), "API keys and token query parameters should not appear");

  const text = redactText("Authorization: Bearer abc.def token=raw-secret");
  assert(text.includes("Bearer [REDACTED]"), "Bearer tokens should be redacted");
  assert(!text.includes("raw-secret"), "Token assignments should be redacted");

  console.log("Logging redaction test passed");
}

main();
