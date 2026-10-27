import { describe, expect, it } from "vitest";
import { PiiVault, redact } from "../src/detectors/pii.js";
import { PII_ENTITIES } from "../src/policy/schema.js";

const ALL = new Set(PII_ENTITIES);

describe("redact", () => {
  it("replaces each entity type with a placeholder", () => {
    const vault = new PiiVault();
    const input =
      "Email jane.doe@acme.io, call +1 (415) 555-0134, card 4111 1111 1111 1111, SSN 123-45-6789, host 10.0.12.7, key sk-proj-abcdefghijklmnopqrstuvwx";
    const { text, counts } = redact(input, ALL, vault);
    expect(text).toBe(
      "Email [EMAIL_1], call [PHONE_1], card [CREDIT_CARD_1], SSN [SSN_1], host [IP_ADDRESS_1], key [SECRET_1]",
    );
    expect(counts).toEqual({ EMAIL: 1, PHONE: 1, CREDIT_CARD: 1, SSN: 1, IP_ADDRESS: 1, SECRET: 1 });
  });

  it("reuses the placeholder for a repeated value", () => {
    const vault = new PiiVault();
    const { text } = redact("a@b.co wrote to c@d.co, then a@b.co replied", ALL, vault);
    expect(text).toBe("[EMAIL_1] wrote to [EMAIL_2], then [EMAIL_1] replied");
  });

  it("ignores digit runs that fail the Luhn check", () => {
    const { text } = redact("Order 4111 1111 1111 1112 shipped", ALL, new PiiVault());
    expect(text).not.toContain("[CREDIT_CARD");
  });

  it("does not treat dates, versions or plain numbers as phones", () => {
    const input = "Released 2024-10-28, version 1.2.3, 12 items, order #12345678";
    expect(redact(input, ALL, new PiiVault()).text).toBe(input);
  });

  it("only redacts enabled entities", () => {
    const { text } = redact("jane@acme.io from 10.0.0.1", new Set(["IP_ADDRESS"] as const), new PiiVault());
    expect(text).toBe("jane@acme.io from [IP_ADDRESS_1]");
  });

  it("round-trips through rehydrate", () => {
    const vault = new PiiVault();
    const input = "Contact jane@acme.io or +92 312 3620503";
    const { text } = redact(input, ALL, vault);
    expect(vault.rehydrate(text)).toBe(input);
  });
});
