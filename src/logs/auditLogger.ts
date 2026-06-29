/**
 * Simple append-only audit trail. Each tool invocation writes one JSON line
 * (JSON Lines / NDJSON format) to `audit.log`, capturing who called what and
 * whether any sensitive data had to be redacted.
 *
 * Design choices:
 *  - Append-only + one record per line → cheap, tail-able, easy to ingest.
 *  - Writes are best-effort: a logging failure must never break the actual
 *    tool response, so errors are caught and reported to stderr only.
 *  - The log path is configurable via the `AUDIT_LOG_PATH` env var, defaulting
 *    to `<cwd>/audit.log`.
 */

import { appendFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { CategoryMatch, ComplianceStatus } from "../compliance/index.js";

/** One structured audit record. */
export interface AuditRecord {
  readonly timestamp: string; // ISO-8601
  readonly tool_called: string;
  readonly user_id_mock: string;
  readonly status_compliance: ComplianceStatus;
  readonly redactions: readonly CategoryMatch[];
  readonly total_redactions: number;
  /** Optional free-form note (e.g. an error summary). */
  readonly note?: string;
}

/** Input needed to record one audit event. */
export interface AuditEventInput {
  readonly tool: string;
  readonly userId: string;
  readonly status: ComplianceStatus;
  readonly redactions?: readonly CategoryMatch[];
  readonly totalRedactions?: number;
  readonly note?: string;
}

export class AuditLogger {
  private readonly logPath: string;

  public constructor(logPath?: string) {
    const fromEnv = process.env["AUDIT_LOG_PATH"];
    const target = logPath ?? fromEnv ?? "audit.log";
    this.logPath = resolve(process.cwd(), target);
  }

  /** Absolute path the logger writes to. Exposed for startup diagnostics. */
  public get path(): string {
    return this.logPath;
  }

  /**
   * Append one audit record. Never throws — logging failures are swallowed and
   * surfaced on stderr so they cannot corrupt the MCP stdout protocol stream.
   */
  public async record(event: AuditEventInput): Promise<void> {
    const record: AuditRecord = {
      timestamp: new Date().toISOString(),
      tool_called: event.tool,
      user_id_mock: event.userId,
      status_compliance: event.status,
      redactions: event.redactions ?? [],
      total_redactions: event.totalRedactions ?? 0,
      ...(event.note !== undefined ? { note: event.note } : {}),
    };

    try {
      await appendFile(this.logPath, `${JSON.stringify(record)}\n`, "utf8");
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      // IMPORTANT: stderr only. stdout is reserved for the MCP JSON-RPC stream.
      process.stderr.write(`[audit] failed to write log: ${reason}\n`);
    }
  }
}
