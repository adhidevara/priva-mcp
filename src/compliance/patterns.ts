/**
 * Detection rules. The order of `REDACTION_RULES` is significant: rules are
 * applied sequentially, and once a value is masked its digits become `X` and
 * can no longer be matched by a later, broader rule. This lets us run the most
 * specific / highest-confidence rules first (email, phone, Luhn-valid cards)
 * before falling back to generic numeric IDs.
 */

import type { KeyRule, RedactionRule } from "./types.js";
import {
  maskCIF,
  maskCreditCard,
  maskEmail,
  maskKeepLast4,
  maskNIK,
  maskPhone,
} from "./masking.js";

/**
 * Luhn checksum validator. Used to keep credit-card detection precise and
 * avoid masking arbitrary 16-digit numbers (e.g. a NIK) as a card.
 */
export function isLuhnValid(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    const char = digits.charAt(i);
    let d = Number.parseInt(char, 10);
    if (Number.isNaN(d)) {
      return false;
    }
    if (double) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * The ordered rule set.
 *
 * 1. email        — unambiguous (`@`), run first.
 * 2. phone        — Indonesian mobile format, run before generic numbers.
 * 3. credit_card  — 13–19 digits, optional separators, Luhn-validated.
 * 4. national_id  — exactly 16 contiguous digits (NIK). CC already consumed.
 * 5. bank_account — 10–15 contiguous digits, the broad numeric fallback.
 */
export const REDACTION_RULES: readonly RedactionRule[] = [
  {
    category: "email",
    label: "Email Address",
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    mask: maskEmail,
  },
  {
    category: "phone",
    label: "Phone Number (ID)",
    // +62 / 62 / 0 prefix, mobile leading 8, total length kept realistic.
    pattern: /(?:\+62|62|0)8[1-9][0-9]{6,11}\b/g,
    mask: maskPhone,
  },
  {
    category: "credit_card",
    label: "Credit / Debit Card",
    // 13–19 digits, optionally split into groups by single space or dash.
    pattern: /\b\d(?:[ -]?\d){12,18}\b/g,
    validate: isLuhnValid,
    mask: maskCreditCard,
  },
  {
    category: "national_id",
    label: "National ID (NIK)",
    pattern: /\b\d{16}\b/g,
    mask: maskKeepLast4,
  },
  {
    category: "bank_account",
    label: "Bank Account Number",
    pattern: /\b\d{10,15}\b/g,
    mask: maskKeepLast4,
  },
];

/**
 * Layer 1 — key-context rules. Evaluated IN ORDER, first match wins. Tokens are
 * matched against the normalized key (see {@link normalizeKey}). Ordering puts
 * `national_id` before `credit_card` so a key like `id_card` (which normalizes
 * to `idcard`, containing the `card` token) is classified as a national ID, not
 * a credit card.
 *
 * Deliberately specific tokens avoid collisions, e.g. `bankaccount` (not bare
 * `account`) so `accountHolder` — a NAME — is never masked as a bank number,
 * and no `id` token so `customerId` is never treated as a NIK.
 */
export const KEY_RULES: readonly KeyRule[] = [
  { category: "email", tokens: ["email"], mask: maskEmail },
  {
    category: "national_id",
    tokens: ["nik", "idcard", "identity", "ktp"],
    mask: maskNIK,
  },
  // CIF is checked before card/account so a `cifNumber` is never mis-handled.
  { category: "cif", tokens: ["cif"], mask: maskCIF },
  {
    category: "credit_card",
    // `pan` (Primary Account Number) + generic card keys.
    tokens: ["pan", "card", "credit"],
    // Spec: run Luhn; if valid, format as XXXX-XXXX-XXXX-1111. The key already
    // signals a card, so an invalid value is still masked (keep-last-4).
    mask: (value: string): string =>
      isLuhnValid(value) ? maskCreditCard(value) : maskKeepLast4(value),
  },
  {
    category: "phone",
    tokens: ["phone", "telp", "mobile", "msisdn"],
    mask: maskPhone,
  },
  {
    category: "bank_account",
    tokens: [
      "bankaccount",
      "rekening",
      "norekening",
      "iban",
      "accountnumber",
      "virtualaccount",
    ],
    mask: maskKeepLast4,
  },
];

/**
 * Amount/balance keys. These hold financial numbers the AI may need for
 * calculation, so they are NEVER turned into an `X` string (that would corrupt
 * the JSON number type). Under strict compliance the engine zeroes the value
 * instead; see {@link ComplianceEngine}.
 */
export const AMOUNT_KEY_TOKENS: readonly string[] = ["balance", "amount"];

/** True when a key denotes a financial amount/balance. */
export function matchAmountKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return AMOUNT_KEY_TOKENS.some((token) => normalized.includes(token));
}

/**
 * Keys that must NEVER cross the proxy. Their presence is a SEVERE breach: the
 * server blocks the whole response rather than masking and forwarding.
 *
 * Matched against whole word-tokens (camelCase + separators are split), so
 * `pin` flags `pinCode`/`mPin` but NOT innocent keys like `shipping`.
 */
export const FORBIDDEN_KEY_WORDS: ReadonlySet<string> = new Set([
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "pin",
  "mpin",
  "otp",
  "cvv",
  "cvc",
  "secret",
  "privatekey",
  "credential",
  "credentials",
]);

/**
 * Split a key into lower-case word tokens: `pinCode` -> ['pin','code'],
 * `bank_account` -> ['bank','account'], `CVV` -> ['cvv'].
 */
export function keyTokens(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((token) => token.length > 0)
    .map((token) => token.toLowerCase());
}

/** True when any word-token of the key is a forbidden (block-on-sight) field. */
export function isForbiddenKey(key: string): boolean {
  return keyTokens(key).some((token) => FORBIDDEN_KEY_WORDS.has(token));
}

/** Lower-case a key and strip non-alphanumerics so `bank_account` -> `bankaccount`. */
export function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Find the first key-context rule whose tokens appear in the given key. */
export function matchKeyRule(key: string): KeyRule | undefined {
  const normalized = normalizeKey(key);
  return KEY_RULES.find((rule) =>
    rule.tokens.some((token) => normalized.includes(token)),
  );
}
