import { messageProblems } from "@openasy/ui";
import { describe, expect, it } from "vitest";
import de from "../src/messages/de.json" with { type: "json" };
import en from "../src/messages/en.json" with { type: "json" };
import tr from "../src/messages/tr.json" with { type: "json" };

describe("screen words", () => {
  it("has every message in every language, with the same placeholders", () => {
    expect(messageProblems({ en, tr, de })).toEqual([]);
  });
});
