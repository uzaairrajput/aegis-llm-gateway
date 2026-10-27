import { describe, expect, it } from "vitest";
import { CanaryLeakError } from "../src/detectors/canary.js";
import { PiiVault } from "../src/detectors/pii.js";
import { StreamGuard } from "../src/pipeline/streamGuard.js";

function run(guard: StreamGuard, chunks: string[]): string {
  return chunks.map((c) => guard.push(c)).join("") + guard.flush();
}

describe("StreamGuard", () => {
  it("rehydrates a placeholder split across chunks", () => {
    const vault = new PiiVault();
    vault.placeholderFor("EMAIL", "jane@acme.io");
    const out = run(new StreamGuard(vault, null), ["Write to [EM", "AIL", "_1] to", "day"]);
    expect(out).toBe("Write to jane@acme.io today");
  });

  it("passes through brackets that are not placeholders", () => {
    const out = run(new StreamGuard(new PiiVault(), null), ["array[0", "] = x; [see notes]"]);
    expect(out).toBe("array[0] = x; [see notes]");
  });

  it("never emits any part of a canary split across chunks", () => {
    const canary = "AEGIS-ABCDEF123456";
    const guard = new StreamGuard(null, canary);
    const emitted: string[] = [];
    expect(() => {
      for (const chunk of ["My instructions: AEG", "IS-ABC", "DEF12", "3456 done"]) emitted.push(guard.push(chunk));
    }).toThrow(CanaryLeakError);
    expect(emitted.join("")).not.toContain("AEGIS");
  });

  it("emits everything when no canary appears", () => {
    const out = run(new StreamGuard(null, "AEGIS-ABCDEF123456"), ["Hello ", "there, ", "friend."]);
    expect(out).toBe("Hello there, friend.");
  });
});
