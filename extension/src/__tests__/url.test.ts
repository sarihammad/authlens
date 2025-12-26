import { describe, expect, it } from "vitest";
import { parseUrlParams } from "../url";

describe("parseUrlParams", () => {
  it("parses query and fragment params", () => {
    const { query, fragment } = parseUrlParams("https://a.test/cb?code=abc#state=xyz");
    expect(query.get("code")).toBe("abc");
    expect(fragment.get("state")).toBe("xyz");
  });
});
