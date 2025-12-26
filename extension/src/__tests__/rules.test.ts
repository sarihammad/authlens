import { describe, expect, it } from "vitest";
import { liveFindingsFromUrl } from "../rules";

describe("liveFindingsFromUrl", () => {
  it("flags token in query", () => {
    const findings = liveFindingsFromUrl("https://example.com/?access_token=tok");
    expect(findings.some((f) => f.id === "TOKEN_IN_QUERY")).toBe(true);
  });

  it("flags token in fragment", () => {
    const findings = liveFindingsFromUrl("https://example.com/#id_token=tok");
    expect(findings.some((f) => f.id === "TOKEN_IN_FRAGMENT")).toBe(true);
  });
});
