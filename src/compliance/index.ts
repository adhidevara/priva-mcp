/**
 * Public surface of the compliance module.
 */

export type {
  SensitiveCategory,
  RedactionRule,
  CategoryMatch,
  RedactionResult,
  ComplianceStatus,
  DetectionMethod,
  JsonPrimitive,
  JsonValue,
  JsonObject,
  KeyRule,
  ObjectRedactionResult,
  CriticalViolation,
} from "./types.js";
export { ComplianceEngine } from "./redactor.js";
export type { ComplianceEngineOptions } from "./redactor.js";
export {
  REDACTION_RULES,
  KEY_RULES,
  AMOUNT_KEY_TOKENS,
  FORBIDDEN_KEY_WORDS,
  isLuhnValid,
  normalizeKey,
  matchKeyRule,
  matchAmountKey,
  keyTokens,
  isForbiddenKey,
} from "./patterns.js";
export {
  maskCreditCard,
  maskKeepLast4,
  maskNIK,
  maskCIF,
  maskEmail,
  maskPhone,
} from "./masking.js";
