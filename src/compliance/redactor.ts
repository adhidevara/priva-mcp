/**
 * The redaction engine — a dual-layer "interceptor" every tool output passes
 * through before it reaches the Claude client.
 *
 *  Layer 1 (stricter, key-based): when scrubbing a structured object, the field
 *    key name decides the masker. An `email` key is masked as email, a `nik` /
 *    `id_card` key as a national ID, a `pan` / `card` key runs the credit-card
 *    masker, a `cif` key is wholesale redacted, etc. The blind global regex
 *    never touches keyed fields, so a 16-digit NIK can never be misclassified
 *    as a Luhn-valid credit card.
 *
 *  Layer 2 (fallback, deep text scan): for raw strings, free text, or fields
 *    whose key is not specific, the engine falls back to the ordered global
 *    regex pipeline (email -> phone -> card -> NIK -> bank).
 *
 *  Numeric safety: `balance` / `amount` fields are NEVER turned into an `X`
 *    string (that would corrupt the JSON number type the AI needs for
 *    calculation). Under strict compliance they are zeroed instead.
 *
 *  Zero-trust block: if a forbidden field (password, PIN, CVV, secret, …) is
 *    present, the result is flagged with a CriticalViolation and the caller is
 *    expected to block the entire payload.
 */

import type {
  CategoryMatch,
  CriticalViolation,
  DetectionMethod,
  JsonValue,
  ObjectRedactionResult,
  RedactionResult,
  RedactionRule,
  SensitiveCategory,
} from "./types.js";
import {
  REDACTION_RULES,
  isForbiddenKey,
  matchAmountKey,
  matchKeyRule,
} from "./patterns.js";

/** Value substituted for amount/balance fields under strict compliance. */
const STRICT_AMOUNT_VALUE = 0;
/** Placeholder written in place of a blocked forbidden field (defense-in-depth). */
const BLOCKED_FIELD_PLACEHOLDER = "REDACTED-SECURITY-VIOLATION";

/** Options controlling engine behavior. */
export interface ComplianceEngineOptions {
  readonly rules?: readonly RedactionRule[];
  /**
   * When `true` (default — banking zero-trust), `balance`/`amount` numbers are
   * zeroed. When `false`, those numbers are passed through untouched so the AI
   * can perform calculations.
   */
  readonly strictMode?: boolean;
}

/** Mutable tally + violation collector for a single scan. */
class ScanState {
  private readonly counts = new Map<string, CategoryMatch>();
  private readonly violationList: CriticalViolation[] = [];

  public add(category: SensitiveCategory, method: DetectionMethod): void {
    const key = `${category}::${method}`;
    const existing = this.counts.get(key);
    this.counts.set(
      key,
      existing
        ? { ...existing, count: existing.count + 1 }
        : { category, method, count: 1 },
    );
  }

  public addViolation(violation: CriticalViolation): void {
    this.violationList.push(violation);
  }

  public matches(): CategoryMatch[] {
    return [...this.counts.values()];
  }

  public violations(): CriticalViolation[] {
    return [...this.violationList];
  }
}

export class ComplianceEngine {
  private readonly rules: readonly RedactionRule[];
  private readonly strictMode: boolean;

  public constructor(options: ComplianceEngineOptions = {}) {
    this.rules = options.rules ?? REDACTION_RULES;
    this.strictMode = options.strictMode ?? true;
  }

  /** Whether numeric amounts are zeroed (strict) or passed through. */
  public get isStrict(): boolean {
    return this.strictMode;
  }

  /**
   * Layer 2 only: scan and mask a single string with the global regex pipeline.
   * Exposed for raw-text payloads and unit testing.
   */
  public redactText(input: string): RedactionResult {
    const state = new ScanState();
    const redactedText = this.scanText(input, state);
    const matches = state.matches();
    const totalRedactions = matches.reduce((sum, m) => sum + m.count, 0);
    return {
      redactedText,
      matches,
      redacted: totalRedactions > 0,
      totalRedactions,
    };
  }

  /**
   * Dual-layer entry point for structured data. Recursively traverses an
   * arbitrary (untrusted) value, applying Layer 1 by key and Layer 2 for the
   * rest, and returns both the scrubbed value and its serialized form plus any
   * critical violations the caller must act on.
   *
   * Accepts `unknown` — the value crosses a trust boundary, so it is narrowed
   * at runtime rather than asserted, keeping the code free of unchecked `any`.
   */
  public redactObject(input: unknown): ObjectRedactionResult {
    const state = new ScanState();
    const redactedValue = this.redactValue(input, undefined, "$", state);
    const matches = state.matches();
    const totalRedactions = matches.reduce((sum, m) => sum + m.count, 0);
    const criticalViolations = state.violations();
    return {
      redactedValue,
      redactedText: JSON.stringify(redactedValue, null, 2),
      matches,
      redacted: totalRedactions > 0,
      totalRedactions,
      criticalViolations,
      hasCriticalViolation: criticalViolations.length > 0,
    };
  }

  /**
   * Recursive traversal.
   * @param keyContext name of the key holding `value` (undefined at the root)
   * @param path       dotted/bracketed location, for incident reporting
   */
  private redactValue(
    value: unknown,
    keyContext: string | undefined,
    path: string,
    state: ScanState,
  ): JsonValue {
    if (typeof value === "string") {
      return this.redactScalarByKey(value, keyContext, state) ?? this.scanText(value, state);
    }

    if (typeof value === "number") {
      // Numeric amounts must keep their type — never stringify to "X".
      if (keyContext !== undefined && matchAmountKey(keyContext)) {
        if (this.strictMode) {
          state.add("financial_amount", "KEY_MATCH");
          return STRICT_AMOUNT_VALUE;
        }
        return value; // non-strict: preserve for AI calculation
      }
      // Other key-matched numbers (e.g. an account number stored as a number)
      // are masked as strings; that is acceptable for identifiers.
      const masked = this.redactScalarByKey(String(value), keyContext, state);
      return masked ?? value;
    }

    if (typeof value === "boolean" || value === null) {
      return value;
    }

    if (Array.isArray(value)) {
      // Elements inherit their parent key's context for masking purposes.
      const items = value as readonly unknown[];
      return items.map((item, index) =>
        this.redactValue(item, keyContext, `${path}[${index}]`, state),
      );
    }

    if (typeof value === "object") {
      const entries = Object.entries(value as Record<string, unknown>);
      const out: Record<string, JsonValue> = {};
      for (const [key, child] of entries) {
        const childPath = `${path}.${key}`;
        // Zero-trust: a forbidden field is a hard block. Record + placeholder,
        // do not recurse into it.
        if (isForbiddenKey(key)) {
          state.addViolation({
            path: childPath,
            key,
            reason: "forbidden sensitive field present in gateway response",
          });
          out[key] = BLOCKED_FIELD_PLACEHOLDER;
          continue;
        }
        out[key] = this.redactValue(child, key, childPath, state);
      }
      return out;
    }

    // undefined / function / symbol / bigint are not JSON-serializable.
    return null;
  }

  /**
   * Apply a Layer 1 key rule to a scalar string. Returns the masked value, or
   * `undefined` when the key is not specific (so the caller can fall back to
   * Layer 2 / leave numbers numeric).
   */
  private redactScalarByKey(
    value: string,
    keyContext: string | undefined,
    state: ScanState,
  ): string | undefined {
    if (keyContext === undefined) {
      return undefined;
    }
    const rule = matchKeyRule(keyContext);
    if (!rule) {
      return undefined;
    }
    state.add(rule.category, "KEY_MATCH");
    return rule.mask(value);
  }

  /** Apply the ordered global regex rules, recording REGEX_MATCH hits. */
  private scanText(input: string, state: ScanState): string {
    let text = input;
    for (const rule of this.rules) {
      rule.pattern.lastIndex = 0; // shared global patterns — reset defensively
      text = text.replace(rule.pattern, (candidate: string): string => {
        if (rule.validate && !rule.validate(candidate)) {
          return candidate; // failed secondary validation (e.g. Luhn)
        }
        state.add(rule.category, "REGEX_MATCH");
        return rule.mask(candidate);
      });
    }
    return text;
  }
}
