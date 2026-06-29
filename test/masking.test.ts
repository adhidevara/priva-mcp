import { test } from "node:test";
import assert from "node:assert/strict";

import {
  maskCreditCard,
  maskKeepLast4,
  maskNIK,
  maskEmail,
  maskPhone,
} from "../src/compliance/index.js";

test("maskCreditCard keeps last 4, regroups into dashed blocks", () => {
  assert.equal(maskCreditCard("4111 1111 1111 1111"), "XXXX-XXXX-XXXX-1111");
  assert.equal(maskCreditCard("4111111111111111"), "XXXX-XXXX-XXXX-1111");
});

test("maskCreditCard handles short input safely", () => {
  assert.equal(maskCreditCard("12"), "XX");
});

test("maskKeepLast4 masks all but last 4 digits", () => {
  assert.equal(maskKeepLast4("1234567890"), "XXXXXX7890");
  assert.equal(maskKeepLast4("9876543210123"), "XXXXXXXXX0123");
});

test("maskNIK keeps last 4 of a 16-digit NIK", () => {
  assert.equal(maskNIK("3173012501900002"), "XXXXXXXXXXXX0002");
});

test("maskEmail partially masks local part and domain, keeps TLD", () => {
  assert.equal(maskEmail("andi.wijaya@example.com"), "a***a@e***.com");
  assert.equal(maskEmail("a@b.co"), "a*@*.co");
});

test("maskEmail degrades safely on malformed input", () => {
  assert.equal(maskEmail("not-an-email"), "***");
});

test("maskPhone keeps leading + and last 3 digits", () => {
  assert.equal(maskPhone("+6281234567890"), "+XXXXXXXXXX890");
  assert.equal(maskPhone("081298765432"), "XXXXXXXXX432");
});
