import { test } from "node:test";
import assert from "node:assert/strict";

import {
  isLuhnValid,
  normalizeKey,
  matchKeyRule,
  matchAmountKey,
  isForbiddenKey,
  keyTokens,
} from "../src/compliance/index.js";

test("isLuhnValid accepts a valid test PAN and rejects junk", () => {
  assert.equal(isLuhnValid("4111111111111111"), true);
  assert.equal(isLuhnValid("4111111111111112"), false);
  assert.equal(isLuhnValid("123"), false); // too short
});

test("normalizeKey lower-cases and strips non-alphanumerics", () => {
  assert.equal(normalizeKey("bank_account"), "bankaccount");
  assert.equal(normalizeKey("Contact-Email"), "contactemail");
  assert.equal(normalizeKey("id_card"), "idcard");
});

test("matchKeyRule classifies sensitive keys", () => {
  assert.equal(matchKeyRule("contactEmail")?.category, "email");
  assert.equal(matchKeyRule("nik")?.category, "national_id");
  assert.equal(matchKeyRule("id_card")?.category, "national_id");
  assert.equal(matchKeyRule("creditCard")?.category, "credit_card");
  assert.equal(matchKeyRule("phone")?.category, "phone");
  assert.equal(matchKeyRule("bankAccount")?.category, "bank_account");
});

test("matchKeyRule does NOT mis-classify near-miss keys", () => {
  // 'customerId' must not be read as a NIK (no bare 'id' token)
  assert.equal(matchKeyRule("customerId"), undefined);
  // 'accountHolder' is a NAME, not a bank account (token is 'bankaccount')
  assert.equal(matchKeyRule("accountHolder"), undefined);
  assert.equal(matchKeyRule("membershipTier"), undefined);
});

test("national_id wins over credit_card for id_card key ordering", () => {
  // 'idcard' contains the 'card' token, but national_id is evaluated first.
  assert.equal(matchKeyRule("id_card")?.category, "national_id");
});

test("banking keys: pan, cifNumber, accountNumber classify correctly", () => {
  assert.equal(matchKeyRule("pan")?.category, "credit_card");
  assert.equal(matchKeyRule("cardNumber")?.category, "credit_card");
  assert.equal(matchKeyRule("cifNumber")?.category, "cif");
  assert.equal(matchKeyRule("cif")?.category, "cif");
  assert.equal(matchKeyRule("accountNumber")?.category, "bank_account");
  assert.equal(matchKeyRule("no_rekening")?.category, "bank_account");
});

test("matchAmountKey flags balance/amount, not unrelated numeric keys", () => {
  assert.equal(matchAmountKey("balance"), true);
  assert.equal(matchAmountKey("amount"), true);
  assert.equal(matchAmountKey("amountIdr"), true);
  assert.equal(matchAmountKey("totalIdr"), false);
  assert.equal(matchAmountKey("accountNumber"), false);
});

test("keyTokens splits camelCase and separators into words", () => {
  assert.deepEqual(keyTokens("pinCode"), ["pin", "code"]);
  assert.deepEqual(keyTokens("bank_account"), ["bank", "account"]);
  assert.deepEqual(keyTokens("CVV"), ["cvv"]);
});

test("isForbiddenKey blocks secret fields by word-token, no false positives", () => {
  assert.equal(isForbiddenKey("password"), true);
  assert.equal(isForbiddenKey("pin"), true);
  assert.equal(isForbiddenKey("pinCode"), true);
  assert.equal(isForbiddenKey("mPin"), true);
  assert.equal(isForbiddenKey("CVV"), true);
  // word-token matching must NOT flag innocent keys that merely contain "pin"
  assert.equal(isForbiddenKey("shippingAddress"), false);
  assert.equal(isForbiddenKey("mappingId"), false);
  assert.equal(isForbiddenKey("accountNumber"), false);
});
