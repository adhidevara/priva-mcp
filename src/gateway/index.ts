/**
 * Public surface of the gateway module.
 */

export { InternalGateway, ResourceNotFoundError } from "./gateway.js";
export {
  findAccount,
  findStatement,
  knownCifNumbers,
} from "./mockData.js";
export type {
  BankAccountProfile,
  AccountStatement,
  StatementTransaction,
} from "./mockData.js";
