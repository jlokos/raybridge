import { describe, expect, it } from "bun:test";
import { normalizeBackendDump, normalizeExtensionsRows } from "./auth-normalize.js";

describe("auth normalization", () => {
  it("normalizes tokenSets object to array", () => {
    const auth = normalizeExtensionsRows([
      {
        name: "ext",
        tokenSets: JSON.stringify({ accessToken: "a" }),
      },
    ]);
    expect(auth.tokens.get("ext")?.length).toBe(1);
    expect(auth.tokens.get("ext")?.[0]?.accessToken).toBe("a");
  });

  it("normalizes tokenSets array", () => {
    const auth = normalizeExtensionsRows([
      {
        name: "ext",
        tokenSets: JSON.stringify([{ accessToken: "a" }, { accessToken: "b" }]),
      },
    ]);
    expect(auth.tokens.get("ext")?.length).toBe(2);
    expect(auth.tokens.get("ext")?.[1]?.accessToken).toBe("b");
  });

  it("normalizes preferences array into object", () => {
    const auth = normalizeExtensionsRows([
      {
        name: "ext",
        preferences: JSON.stringify([
          { name: "foo", value: "bar" },
          { name: "n", value: 1 },
        ]),
      },
    ]);
    expect(auth.prefs.ext.foo).toBe("bar");
    expect(auth.prefs.ext.n).toBe(1);
  });

  it("ignores invalid JSON", () => {
    const auth = normalizeExtensionsRows([
      { name: "ext", tokenSets: "{", preferences: "[" },
    ]);
    expect(auth.tokens.has("ext")).toBe(false);
    expect(auth.prefs.ext).toBeUndefined();
  });

  it("normalizes backend dump JSON", () => {
    const auth = normalizeBackendDump({
      tokens: { ext: [{ accessToken: "a" }] },
      prefs: { ext: { foo: "bar" } },
    });
    expect(auth.tokens.get("ext")?.[0]?.accessToken).toBe("a");
    expect(auth.prefs.ext.foo).toBe("bar");
  });
});

