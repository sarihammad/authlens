import { describe, expect, it } from "vitest";
import { redactUrl } from "../redact";

describe("redactUrl", () => {
  it("redacts sensitive query values", () => {
    const url = "https://example.com/callback?code=abc123&state=ok";
    const redacted = redactUrl(url);
    expect(redacted).toMatch(/code=%3Credacted(?:%20|\+)len%3D6%3E/);
    expect(redacted).toContain("state=ok");
  });

  it("redacts sensitive fragment values", () => {
    const url = "https://example.com/#access_token=token123&id_token=id123";
    const redacted = redactUrl(url);
    expect(redacted).toMatch(/access_token=%3Credacted(?:%20|\+)len%3D8%3E/);
    expect(redacted).toMatch(/id_token=%3Credacted(?:%20|\+)len%3D5%3E/);
  });
});
