import { describe, expect, it } from "vitest";
import { hostMatchesAllowlist, normalizeAllowlistInput } from "../allowlist";

describe("allowlist", () => {
  it("normalizes input into unique lowercase hosts", () => {
    const list = normalizeAllowlistInput("Example.com\n*.example.com\nHTTPS://Foo.com");
    expect(list).toEqual(["example.com", "*.example.com", "foo.com"]);
  });

  it("matches exact and wildcard domains", () => {
    const allowlist = ["example.com", "*.example.net"];
    expect(hostMatchesAllowlist("example.com", allowlist)).toBe(true);
    expect(hostMatchesAllowlist("api.example.com", allowlist)).toBe(true);
    expect(hostMatchesAllowlist("foo.example.net", allowlist)).toBe(true);
    expect(hostMatchesAllowlist("example.org", allowlist)).toBe(false);
  });
});
