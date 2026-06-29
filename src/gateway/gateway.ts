/**
 * The gateway is the proxy layer that talks to the "internal" API resource.
 * It returns RAW, unredacted data — scrubbing is the compliance engine's job,
 * applied downstream in the server. Keeping the two concerns separate means the
 * gateway can be swapped for a real internal API client without touching the
 * privacy logic.
 */

import {
  findAccount,
  findStatement,
  knownCifNumbers,
  type AccountStatement,
  type BankAccountProfile,
} from "./mockData.js";

/** Raised when a requested resource does not exist in the backend. */
export class ResourceNotFoundError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "ResourceNotFoundError";
  }
}

export class InternalGateway {
  /**
   * Fetch a raw banking profile by CIF number. Throws
   * {@link ResourceNotFoundError} if the id is unknown so the caller can
   * translate it into a clean tool error.
   */
  public getCustomerProfile(cifNumber: string): BankAccountProfile {
    const profile = findAccount(cifNumber);
    if (!profile) {
      throw new ResourceNotFoundError(
        `No account found for CIF "${cifNumber}". Known ids: ${knownCifNumbers().join(
          ", ",
        )}`,
      );
    }
    return profile;
  }

  /**
   * Fetch a raw account statement by CIF number. Throws
   * {@link ResourceNotFoundError} if no statement exists for the id.
   */
  public getFinancialReport(cifNumber: string): AccountStatement {
    const statement = findStatement(cifNumber);
    if (!statement) {
      throw new ResourceNotFoundError(
        `No statement found for CIF "${cifNumber}". Known ids: ${knownCifNumbers().join(
          ", ",
        )}`,
      );
    }
    return statement;
  }
}
