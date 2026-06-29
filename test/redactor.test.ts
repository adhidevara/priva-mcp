import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ComplianceEngine,
  type CategoryMatch,
  type JsonValue,
} from "../src/compliance/index.js";

const engine = new ComplianceEngine();

/** Narrow a JsonValue we know is an object for ergonomic assertions. */
function asObject(value: JsonValue): Record<string, JsonValue> {
  assert.ok(
    typeof value === "object" && value !== null && !Array.isArray(value),
    "expected a JSON object",
  );
  return value as Record<string, JsonValue>;
}

function find(
  matches: readonly CategoryMatch[],
  category: string,
): CategoryMatch | undefined {
  return matches.find((m) => m.category === category);
}

test("Layer 2: redactText scans free text via global regex (REGEX_MATCH)", () => {
  const r = engine.redactText("ping a@b.co or 081298765432");
  assert.equal(r.redacted, true);
  assert.equal(find(r.matches, "email")?.method, "REGEX_MATCH");
  assert.equal(find(r.matches, "phone")?.method, "REGEX_MATCH");
});

test("Layer 1: redactObject masks by key (KEY_MATCH)", () => {
  const r = engine.redactObject({
    email: "andi.wijaya@example.com",
    phone: "+6281234567890",
    nik: "3173012501900002",
    creditCard: "4111 1111 1111 1111",
    bankAccount: "1234567890",
  });
  const out = asObject(r.redactedValue);

  assert.equal(out["email"], "a***a@e***.com");
  assert.equal(out["phone"], "+XXXXXXXXXX890");
  assert.equal(out["nik"], "XXXXXXXXXXXX0002");
  assert.equal(out["creditCard"], "XXXX-XXXX-XXXX-1111");
  assert.equal(out["bankAccount"], "XXXXXX7890");

  assert.equal(r.totalRedactions, 5);
  for (const m of r.matches) {
    assert.equal(m.method, "KEY_MATCH");
  }
});

test("false-positive fixed: Luhn-valid value in nik key -> national_id, not credit_card", () => {
  // 4111111111111111 is a Luhn-valid card number, but the KEY says NIK.
  const r = engine.redactObject({ nik: "4111111111111111" });
  const out = asObject(r.redactedValue);

  assert.equal(out["nik"], "XXXXXXXXXXXX1111"); // NIK mask, not grouped card mask
  assert.equal(find(r.matches, "national_id")?.method, "KEY_MATCH");
  assert.equal(find(r.matches, "credit_card"), undefined);
});

test("accountHolder name is NOT masked as a bank account", () => {
  const r = engine.redactObject({ accountHolder: "Andi Wijaya" });
  const out = asObject(r.redactedValue);
  assert.equal(out["accountHolder"], "Andi Wijaya");
  assert.equal(r.redacted, false);
});

test("Layer 2 fallback inside object: unspecific key gets a deep regex scan", () => {
  const r = engine.redactObject({
    notes: "contact a@b.co card 4111111111111111",
  });
  const out = asObject(r.redactedValue);

  assert.match(String(out["notes"]), /a\*@\*\.co/);
  assert.match(String(out["notes"]), /XXXX-XXXX-XXXX-1111/);
  assert.equal(find(r.matches, "email")?.method, "REGEX_MATCH");
  assert.equal(find(r.matches, "credit_card")?.method, "REGEX_MATCH");
});

test("recursive traversal handles nested objects and arrays", () => {
  const r = engine.redactObject({
    users: [{ email: "a@b.co", id_card: "3173012501900002" }],
  });
  const root = asObject(r.redactedValue);
  const users = root["users"];
  assert.ok(Array.isArray(users));
  const first = asObject(users[0] as JsonValue);

  assert.equal(first["email"], "a*@*.co");
  assert.equal(first["id_card"], "XXXXXXXXXXXX0002");
  assert.equal(r.totalRedactions, 2);
});

test("numbers and booleans pass through; clean object reports no redaction", () => {
  const r = engine.redactObject({
    membershipTier: "gold",
    active: true,
    totalIdr: 32_750_000,
  });
  const out = asObject(r.redactedValue);

  assert.equal(out["membershipTier"], "gold");
  assert.equal(out["active"], true);
  assert.equal(out["totalIdr"], 32_750_000);
  assert.equal(r.redacted, false);
  assert.equal(r.totalRedactions, 0);
});

// ---------------------------------------------------------------------------
// Banking field-level redaction
// ---------------------------------------------------------------------------

test("banking profile: cif, pan, accountNumber masked by key", () => {
  const r = engine.redactObject({
    cifNumber: "CIF-7782001",
    customerName: "Andi Wijaya",
    accountNumber: "0012345678901",
    pan: "4111111111111111",
    phoneNumber: "+6281234567890",
  });
  const out = asObject(r.redactedValue);

  assert.equal(out["cifNumber"], "REDACTED-CIF");
  assert.equal(out["customerName"], "Andi Wijaya"); // names are not masked
  assert.equal(out["accountNumber"], "XXXXXXXXX8901");
  assert.equal(out["pan"], "XXXX-XXXX-XXXX-1111"); // Luhn-valid -> grouped
  assert.equal(out["phoneNumber"], "+XXXXXXXXXX890");

  assert.equal(find(r.matches, "cif")?.method, "KEY_MATCH");
  assert.equal(find(r.matches, "credit_card")?.method, "KEY_MATCH");
  assert.equal(find(r.matches, "bank_account")?.method, "KEY_MATCH");
});

test("strict mode zeroes balance/amount but keeps them as NUMBERS", () => {
  const r = engine.redactObject({
    balance: 15_750_000,
    transactions: [{ description: "Salary", amount: 22_000_000 }],
  });
  const out = asObject(r.redactedValue);

  assert.equal(out["balance"], 0);
  assert.equal(typeof out["balance"], "number"); // type preserved, not "X"
  const txns = out["transactions"];
  assert.ok(Array.isArray(txns));
  const first = asObject(txns[0] as JsonValue);
  assert.equal(first["amount"], 0);
  assert.equal(typeof first["amount"], "number");
  assert.equal(find(r.matches, "financial_amount")?.method, "KEY_MATCH");
});

test("non-strict mode passes amounts through untouched for AI calc", () => {
  const lenient = new ComplianceEngine({ strictMode: false });
  const r = lenient.redactObject({ balance: 15_750_000 });
  const out = asObject(r.redactedValue);

  assert.equal(out["balance"], 15_750_000);
  assert.equal(r.redacted, false);
});

// ---------------------------------------------------------------------------
// Zero-trust hard block on forbidden fields
// ---------------------------------------------------------------------------

test("forbidden field triggers a critical violation and is not forwarded", () => {
  const r = engine.redactObject({
    cifNumber: "CIF-7782001",
    password: "hunter2",
    accountNumber: "0012345678901",
  });
  const out = asObject(r.redactedValue);

  assert.equal(r.hasCriticalViolation, true);
  assert.equal(r.criticalViolations.length, 1);
  assert.equal(r.criticalViolations[0]?.key, "password");
  assert.equal(out["password"], "REDACTED-SECURITY-VIOLATION");
  // other fields are still scrubbed normally
  assert.equal(out["cifNumber"], "REDACTED-CIF");
});

test("forbidden field nested in an array is detected with a path", () => {
  const r = engine.redactObject({
    cards: [{ pan: "4111111111111111", pin: "1234" }],
  });
  assert.equal(r.hasCriticalViolation, true);
  assert.equal(r.criticalViolations[0]?.key, "pin");
  assert.equal(r.criticalViolations[0]?.path, "$.cards[0].pin");
});
