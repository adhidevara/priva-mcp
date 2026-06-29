/**
 * Pure masking helpers. Each function takes a raw sensitive value and returns
 * a masked representation that preserves just enough shape to remain useful
 * (e.g. last 4 digits of a card) without leaking the secret.
 *
 * These functions are deterministic and side-effect free so they are trivial
 * to unit test.
 */

/** Extract only the digit characters from a string. */
function digitsOf(value: string): string {
  return value.replace(/\D/g, "");
}

/**
 * Mask a credit-card / long card-like number, keeping the last 4 digits and
 * regrouping into 4-digit blocks: `4111 1111 1111 1234` -> `XXXX-XXXX-XXXX-1234`.
 */
export function maskCreditCard(value: string): string {
  const digits = digitsOf(value);
  if (digits.length <= 4) {
    return "X".repeat(digits.length);
  }
  const last4 = digits.slice(-4);
  const masked = "X".repeat(digits.length - 4) + last4;
  // Regroup into blocks of 4 separated by dashes.
  const grouped = masked.match(/.{1,4}/g);
  return grouped ? grouped.join("-") : masked;
}

/**
 * Mask a generic numeric identifier (bank account, NIK), keeping the last 4
 * digits: `3173012501900002` -> `XXXXXXXXXXXX0002`.
 */
export function maskKeepLast4(value: string): string {
  const digits = digitsOf(value);
  if (digits.length <= 4) {
    return "X".repeat(digits.length);
  }
  return "X".repeat(digits.length - 4) + digits.slice(-4);
}

/**
 * Mask an Indonesian National ID (NIK) or similar sensitive identifier,
 * keeping only the last 4 digits: `3173012501900002` -> `XXXXXXXXXXXX0002`.
 * Distinct, named entry point so key-context redaction reads clearly.
 */
export function maskNIK(value: string): string {
  return maskKeepLast4(value);
}

/**
 * Fully redact a banking CIF (Customer Information File) number. The CIF is a
 * master key that links every product a customer holds, so no partial value is
 * ever returned — it is replaced wholesale.
 */
export function maskCIF(_value: string): string {
  return "REDACTED-CIF";
}

/**
 * Partially mask an email: keep the first/last char of the local part and the
 * first char of the domain name, preserving the TLD.
 * `john.doe@example.com` -> `j***e@e***.com`
 */
export function maskEmail(value: string): string {
  const atIndex = value.lastIndexOf("@");
  if (atIndex <= 0) {
    return "***";
  }
  const local = value.slice(0, atIndex);
  const domain = value.slice(atIndex + 1);

  const maskedLocal =
    local.length <= 2
      ? `${local.charAt(0)}*`
      : `${local.charAt(0)}***${local.charAt(local.length - 1)}`;

  const dotIndex = domain.lastIndexOf(".");
  if (dotIndex <= 0) {
    return `${maskedLocal}@***`;
  }
  const name = domain.slice(0, dotIndex);
  const tld = domain.slice(dotIndex); // includes leading dot
  const maskedName = name.length <= 1 ? "*" : `${name.charAt(0)}***`;

  return `${maskedLocal}@${maskedName}${tld}`;
}

/**
 * Partially mask a phone number, keeping the leading `+` (if present) and the
 * last 3 digits: `+6281234567890` -> `+XXXXXXXXXX890`.
 */
export function maskPhone(value: string): string {
  const hasPlus = value.trim().startsWith("+");
  const digits = digitsOf(value);
  const keep = 3;
  if (digits.length <= keep) {
    return (hasPlus ? "+" : "") + "X".repeat(digits.length);
  }
  const masked = "X".repeat(digits.length - keep) + digits.slice(-keep);
  return (hasPlus ? "+" : "") + masked;
}
