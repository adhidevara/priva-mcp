/**
 * Core type definitions for the compliance / redaction engine.
 *
 * Everything is strongly typed — no `any`. Categories are a closed union so
 * the audit layer and any future policy engine can reason exhaustively over
 * what kinds of sensitive data the proxy knows how to detect.
 */

/** Closed set of sensitive-data categories the engine can detect and mask. */
export type SensitiveCategory =
  | "credit_card" // also covers debit-card PAN (Primary Account Number)
  | "bank_account"
  | "national_id" // Indonesian NIK (16 digits) or similar sensitive IDs
  | "cif" // banking Customer Information File number
  | "financial_amount" // balances / transaction amounts (numeric-safe handling)
  | "email"
  | "phone";

/** A single redaction rule: how to find a category and how to mask it. */
export interface RedactionRule {
  /** Category this rule detects. */
  readonly category: SensitiveCategory;
  /** Human-readable label, used in logs and debugging. */
  readonly label: string;
  /** Global RegExp used to locate candidate matches. MUST have the `g` flag. */
  readonly pattern: RegExp;
  /**
   * Optional secondary validation (e.g. Luhn check for credit cards) to cut
   * false positives. Returning `false` leaves the candidate untouched.
   */
  readonly validate?: (candidate: string) => boolean;
  /** Produces the masked replacement for a confirmed match. */
  readonly mask: (candidate: string) => string;
}

/**
 * How a value was detected:
 *  - KEY_MATCH  : the object key name identified the field (Layer 1, stricter).
 *  - REGEX_MATCH: the value matched a global pattern in a deep text scan (Layer 2).
 */
export type DetectionMethod = "KEY_MATCH" | "REGEX_MATCH";

/** Per-(category, method) tally of how many values were redacted in one scan. */
export interface CategoryMatch {
  readonly category: SensitiveCategory;
  readonly method: DetectionMethod;
  readonly count: number;
}

/** JSON value model — keeps `redactObject` fully typed without `any`. */
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };

/**
 * A key-context (Layer 1) rule: if a field's key name contains one of the
 * tokens, the matching masker is applied directly — bypassing the blind global
 * regex so a 16-digit NIK can never be mistaken for a credit card.
 */
export interface KeyRule {
  readonly category: SensitiveCategory;
  /** Normalized substrings (lower-case, alphanumeric only) to look for in keys. */
  readonly tokens: readonly string[];
  readonly mask: (value: string) => string;
}

/** Result of running the redaction engine over a piece of text. */
export interface RedactionResult {
  /** The text after masking. Equal to the input when nothing matched. */
  readonly redactedText: string;
  /** Breakdown of what was redacted, by category. Empty when clean. */
  readonly matches: readonly CategoryMatch[];
  /** Convenience flag: `true` if at least one value was masked. */
  readonly redacted: boolean;
  /** Total number of individual values masked across all categories. */
  readonly totalRedactions: number;
}

/**
 * A SEVERE compliance breach: a field that must never traverse the proxy
 * (password, PIN, CVV, secret, …) appeared in the gateway response. When this
 * fires the server blocks the entire payload — it does not attempt to mask and
 * forward.
 */
export interface CriticalViolation {
  /** Dotted/bracketed location of the offending field, e.g. `users[0].pin`. */
  readonly path: string;
  /** The offending key name as it appeared in the payload. */
  readonly key: string;
  /** Human + machine readable reason, surfaced in the ELK incident log. */
  readonly reason: string;
}

/** Result of running the dual-layer engine over a structured JSON value. */
export interface ObjectRedactionResult {
  /** The input with sensitive values masked in place. */
  readonly redactedValue: JsonValue;
  /** Pretty-printed JSON of {@link redactedValue}, ready to ship to the client. */
  readonly redactedText: string;
  /** Breakdown of what was redacted, by category and detection method. */
  readonly matches: readonly CategoryMatch[];
  readonly redacted: boolean;
  readonly totalRedactions: number;
  /** Any SEVERE breaches found. Non-empty ⇒ the caller MUST block the response. */
  readonly criticalViolations: readonly CriticalViolation[];
  /** Convenience flag: `true` when {@link criticalViolations} is non-empty. */
  readonly hasCriticalViolation: boolean;
}

/** Compliance status used by the audit trail. */
export type ComplianceStatus = "CLEAN" | "REDACTED" | "BLOCKED";
