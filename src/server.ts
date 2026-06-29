#!/usr/bin/env node
/**
 * Priva-MCP — entry point.
 *
 * Wiring: Claude (client)  ⇄  THIS MCP SERVER  ⇄  Internal Gateway (Core/IST API)
 *
 * Every tool call follows the same pipeline:
 *   1. Gateway fetches RAW data from the internal banking resource.
 *   2. The ComplianceEngine scans + masks any sensitive values (the
 *      man-in-the-middle interceptor), with field-level (key-aware) rules.
 *   3. If a forbidden field (password/PIN/CVV/secret) is present, the response
 *      is BLOCKED entirely — a safe error goes to Claude, a detailed JSON
 *      incident goes to stderr (ELK/Logstash), nothing leaks to stdout.
 *   4. The AuditLogger records who called what and the compliance status.
 *   5. Only the SCRUBBED payload is returned to the Claude client.
 *
 * Transport is stdio: stdout carries the JSON-RPC stream and must stay clean;
 * ALL diagnostics and incident logs go to stderr.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import {
  ComplianceEngine,
  type ComplianceStatus,
  type CriticalViolation,
} from "./compliance/index.js";
import { InternalGateway, ResourceNotFoundError } from "./gateway/index.js";
import { AuditLogger } from "./logs/index.js";

const SERVER_NAME = "priva-mcp";
const SERVER_VERSION = "1.0.0";
const DEFAULT_USER_ID = "mock-user-001";

/** Generic, information-free messages returned to the client on failure. */
const SAFE_BLOCK_MESSAGE =
  "Error: response blocked by privacy & compliance policy (a forbidden " +
  "sensitive field was detected). The incident has been logged.";
const SAFE_ERROR_MESSAGE =
  "Error: request failed due to an internal compliance error. The incident " +
  "has been logged.";

/**
 * Strict compliance (default ON for banking zero-trust): balance/amount numbers
 * are zeroed. Set COMPLIANCE_STRICT=false to pass amounts through for AI calc.
 */
const STRICT_MODE =
  (process.env["COMPLIANCE_STRICT"] ?? "true").toLowerCase() !== "false";

/** Shared singletons for the lifetime of the process. */
const engine = new ComplianceEngine({ strictMode: STRICT_MODE });
const gateway = new InternalGateway();
const audit = new AuditLogger();

/** A function that pulls raw (unredacted) data from the gateway. */
type RawFetcher = (cifNumber: string) => unknown;

/** Build a standard text tool result. */
function textResult(text: string, isError = false): CallToolResult {
  return {
    content: [{ type: "text", text }],
    ...(isError ? { isError: true } : {}),
  };
}

/** Write one ECS-style JSON line to stderr for ELK / Logstash ingestion. */
function writeIncident(record: Readonly<Record<string, unknown>>): void {
  // stderr ONLY — stdout is reserved for the MCP JSON-RPC stream.
  process.stderr.write(`${JSON.stringify(record)}\n`);
}

/** Emit a SEVERE compliance breach (forbidden field present). */
function emitSecurityIncident(params: {
  readonly tool: string;
  readonly userId: string;
  readonly violations: readonly CriticalViolation[];
}): void {
  writeIncident({
    "@timestamp": new Date().toISOString(),
    "log.level": "error",
    "log.logger": `${SERVER_NAME}.compliance`,
    "event.kind": "alert",
    "event.category": "intrusion_detection",
    "event.action": "compliance.critical_violation",
    "event.outcome": "blocked",
    tool: params.tool,
    user_id_mock: params.userId,
    violation_count: params.violations.length,
    violations: params.violations.map((v) => ({
      path: v.path,
      key: v.key,
      reason: v.reason,
    })),
    message:
      "Forbidden sensitive field detected in gateway response; response " +
      "blocked before reaching the client.",
  });
}

/** Emit an unexpected pipeline error without leaking it to the client. */
function emitErrorIncident(params: {
  readonly tool: string;
  readonly userId: string;
  readonly error: unknown;
}): void {
  const { error } = params;
  writeIncident({
    "@timestamp": new Date().toISOString(),
    "log.level": "error",
    "log.logger": `${SERVER_NAME}.compliance`,
    "event.kind": "event",
    "event.category": "process",
    "event.action": "compliance.pipeline_error",
    "event.outcome": "failure",
    tool: params.tool,
    user_id_mock: params.userId,
    "error.type": error instanceof Error ? error.name : typeof error,
    "error.message": error instanceof Error ? error.message : String(error),
    "error.stack_trace": error instanceof Error ? error.stack ?? null : null,
    message: "Compliance pipeline error; a safe error was returned to the client.",
  });
}

/**
 * The compliance pipeline shared by every tool. Fetch raw → redact → (block on
 * critical) → audit → return only the scrubbed payload. Any unexpected failure
 * is contained: a generic message goes to the client, full detail to stderr.
 */
async function runCompliancePipeline(params: {
  readonly toolName: string;
  readonly cifNumber: string;
  readonly userId: string;
  readonly fetcher: RawFetcher;
}): Promise<CallToolResult> {
  const { toolName, cifNumber, userId, fetcher } = params;

  try {
    let raw: unknown;
    try {
      raw = fetcher(cifNumber);
    } catch (error) {
      if (error instanceof ResourceNotFoundError) {
        await audit.record({
          tool: toolName,
          userId,
          status: "CLEAN",
          note: `resource not found: ${error.message}`,
        });
        return textResult(`Error: ${error.message}`, true);
      }
      throw error; // handled by the outer catch (no leak to client)
    }

    const result = engine.redactObject(raw);

    // Zero-trust hard stop: never mask-and-forward a forbidden field.
    if (result.hasCriticalViolation) {
      emitSecurityIncident({
        tool: toolName,
        userId,
        violations: result.criticalViolations,
      });
      await audit.record({
        tool: toolName,
        userId,
        status: "BLOCKED",
        redactions: result.matches,
        totalRedactions: result.totalRedactions,
        note: `critical violation: ${result.criticalViolations
          .map((v) => v.key)
          .join(", ")}`,
      });
      return textResult(SAFE_BLOCK_MESSAGE, true);
    }

    const status: ComplianceStatus = result.redacted ? "REDACTED" : "CLEAN";
    await audit.record({
      tool: toolName,
      userId,
      status,
      redactions: result.matches,
      totalRedactions: result.totalRedactions,
    });

    return textResult(result.redactedText);
  } catch (error) {
    emitErrorIncident({ tool: toolName, userId, error });
    await audit.record({
      tool: toolName,
      userId,
      status: "BLOCKED",
      note: "internal error (see stderr incident log)",
    });
    return textResult(SAFE_ERROR_MESSAGE, true);
  }
}

function createServer(): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  const sharedInputSchema = {
    cifNumber: z
      .string()
      .min(1)
      .describe('Customer CIF number to look up, e.g. "CIF-7782001".'),
    requestedBy: z
      .string()
      .min(1)
      .optional()
      .describe("Mock user id of the requester, recorded in the audit trail."),
  } as const;

  server.registerTool(
    "get_customer_profile",
    {
      title: "Get Customer Profile",
      description:
        "Retrieve a customer's banking profile from the core system by CIF " +
        "number. Sensitive fields (CIF, account number, debit-card PAN, email, " +
        "phone) are automatically masked, and balances are protected, by the " +
        "privacy layer before being returned.",
      inputSchema: sharedInputSchema,
    },
    async ({ cifNumber, requestedBy }): Promise<CallToolResult> =>
      runCompliancePipeline({
        toolName: "get_customer_profile",
        cifNumber,
        userId: requestedBy ?? DEFAULT_USER_ID,
        fetcher: (id) => gateway.getCustomerProfile(id),
      }),
  );

  server.registerTool(
    "get_financial_report",
    {
      title: "Get Financial Report",
      description:
        "Retrieve a customer's account statement from the core system by CIF " +
        "number. Sensitive fields are masked and amounts are protected by the " +
        "privacy layer before being returned.",
      inputSchema: sharedInputSchema,
    },
    async ({ cifNumber, requestedBy }): Promise<CallToolResult> =>
      runCompliancePipeline({
        toolName: "get_financial_report",
        cifNumber,
        userId: requestedBy ?? DEFAULT_USER_ID,
        fetcher: (id) => gateway.getFinancialReport(id),
      }),
  );

  return server;
}

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Diagnostics go to stderr — stdout is the JSON-RPC channel and must stay clean.
  process.stderr.write(
    `[${SERVER_NAME}] v${SERVER_VERSION} ready on stdio. ` +
      `strict=${String(STRICT_MODE)} audit=${audit.path}\n`,
  );
}

main().catch((error: unknown) => {
  const reason =
    error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[${SERVER_NAME}] fatal: ${reason}\n`);
  process.exit(1);
});
