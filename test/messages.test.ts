import { catalogueProblems } from "@openasy/ui";
import { describe, expect, it } from "vitest";
import { MESSAGES } from "../src/messages.ts";

describe("screen words", () => {
  it("has every message in every language, with the same placeholders", () => {
    expect(catalogueProblems(MESSAGES)).toEqual([]);
  });
});
