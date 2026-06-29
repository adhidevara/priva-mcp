/**
 * Mock "internal" datastore. Simulates responses from an internal API (the
 * kind that backs a banking-style app). The gateway returns RAW, unredacted
 * records on purpose — scrubbing is the compliance engine's job.
 *
 * Field names match a realistic banking payload (`accountNumber`, `cifNumber`,
 * `pan`, `phoneNumber`, `balance`, `customerName`) so the key-context
 * (Layer 1) redaction rules apply.
 *
 * NOTE: every value below is fake/test data. The `pan` values are valid only in
 * the Luhn-checksum sense (standard test PANs).
 */

/** A customer's profile as returned by the internal API. */
export interface BankAccountProfile {
  readonly cifNumber: string; // Customer Information File — master key
  readonly customerName: string;
  readonly accountNumber: string;
  readonly pan: string; // debit-card Primary Account Number
  readonly phoneNumber: string;
  readonly email: string;
  readonly balance: number; // numeric — AI may need it for calculation
  readonly currency: string;
  readonly branch: string;
}

/** One line on an account statement. */
export interface StatementTransaction {
  readonly date: string;
  readonly description: string;
  readonly amount: number; // signed: credit (+) / debit (-)
}

/** A customer's account statement / financial report. */
export interface AccountStatement {
  readonly reportId: string;
  readonly cifNumber: string;
  readonly accountNumber: string;
  readonly customerName: string;
  readonly period: string;
  readonly balance: number;
  readonly transactions: readonly StatementTransaction[];
}

const ACCOUNTS: ReadonlyMap<string, BankAccountProfile> = new Map([
  [
    "CIF-7782001",
    {
      cifNumber: "CIF-7782001",
      customerName: "Andi Wijaya",
      accountNumber: "0012345678901",
      pan: "4111111111111111",
      phoneNumber: "+6281234567890",
      email: "andi.wijaya@example.com",
      balance: 15_750_000,
      currency: "IDR",
      branch: "KCP Sudirman Jakarta",
    },
  ],
  [
    "CIF-7782002",
    {
      cifNumber: "CIF-7782002",
      customerName: "Siti Nurhaliza",
      accountNumber: "0098765432109",
      pan: "5500000000000004",
      phoneNumber: "081298765432",
      email: "siti.n@contoso.co.id",
      balance: 48_250_500,
      currency: "IDR",
      branch: "KCP Asia Afrika Bandung",
    },
  ],
]);

const STATEMENTS: ReadonlyMap<string, AccountStatement> = new Map([
  [
    "CIF-7782001",
    {
      reportId: "STMT-2026-7782001",
      cifNumber: "CIF-7782001",
      accountNumber: "0012345678901",
      customerName: "Andi Wijaya",
      period: "2026-Q2",
      balance: 15_750_000,
      transactions: [
        { date: "2026-04-02", description: "Opening balance", amount: 15_000_000 },
        { date: "2026-04-18", description: "QRIS payment", amount: -1_250_000 },
        { date: "2026-05-25", description: "Salary credit", amount: 22_000_000 },
        { date: "2026-06-10", description: "Card spend", amount: -20_000_000 },
      ],
    },
  ],
  [
    "CIF-7782002",
    {
      reportId: "STMT-2026-7782002",
      cifNumber: "CIF-7782002",
      accountNumber: "0098765432109",
      customerName: "Siti Nurhaliza",
      period: "2026-Q2",
      balance: 48_250_500,
      transactions: [
        { date: "2026-04-05", description: "Opening balance", amount: 45_000_000 },
        { date: "2026-05-12", description: "Investment payout", amount: 12_500_000 },
        { date: "2026-06-20", description: "Transfer out", amount: -9_249_500 },
      ],
    },
  ],
]);

/** Look up a banking profile by CIF number. Returns `undefined` if not found. */
export function findAccount(cifNumber: string): BankAccountProfile | undefined {
  return ACCOUNTS.get(cifNumber);
}

/** Look up an account statement by CIF number. Returns `undefined` if missing. */
export function findStatement(cifNumber: string): AccountStatement | undefined {
  return STATEMENTS.get(cifNumber);
}

/** All known CIF numbers — handy for error messages and tests. */
export function knownCifNumbers(): readonly string[] {
  return [...ACCOUNTS.keys()];
}
