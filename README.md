# Priva-MCP — Privacy & Compliance Layer

> 🇮🇩 Versi Bahasa Indonesia: [README.id.md](README.id.md)

A man-in-the-middle **MCP proxy** that sits between Claude (the client) and an
an **internal API** (the resource). It intercepts the output of
internal tools and **automatically masks sensitive banking data** — CIF numbers,
account numbers, debit-card PANs, balances, emails, phone numbers, national IDs —
*before* anything is returned to Claude. If a field that must never leave the
bank (password, PIN, CVV, secret) is detected, the **entire response is blocked**.
Every call is recorded in an append-only audit trail, and severe breaches raise a
structured incident log for an enterprise SIEM (ELK / Logstash).

```
Claude (Client)  ⇄  Priva-MCP (this proxy)  ⇄  Internal API
                       │
                       ├── compliance engine  → dual-layer redaction (key + regex)
                       ├── zero-trust block   → drops response on forbidden fields
                       ├── audit logger       → audit.log (JSON Lines)
                       └── incident logger     → stderr ECS JSON (ELK / Logstash)
```

Design principle: **zero-trust toward PII**. stdout is reserved for the MCP
JSON-RPC stream and never carries data leaks; all diagnostics and incidents go to
stderr; sensitive values are masked at the field level, not by blind global regex.

---

## Table of contents

- [Features](#features)
- [Project structure](#project-structure)
- [Requirements](#requirements)
- [Install](#install)
- [Run locally](#run-locally)
- [Environment variables](#environment-variables)
- [Tools & mock data](#tools--mock-data)
- [Redaction reference](#redaction-reference)
- [Strict mode & numeric safety](#strict-mode--numeric-safety)
- [Zero-trust block & ELK incident logging](#zero-trust-block--elk-incident-logging)
- [Audit log format](#audit-log-format)
- [Quick manual smoke test](#quick-manual-smoke-test)
- [Connect to Claude Desktop](#connect-to-claude-desktop)
- [Testing](#testing)
- [How detection works](#how-detection-works)
- [Extending toward production](#extending-toward-production)

---

## Features

- **Official MCP TypeScript SDK** (`@modelcontextprotocol/sdk`) over stdio.
- **Two mock tools** that simulate pulling data from an internal API:
  - `get_customer_profile` — banking profile by CIF.
  - `get_financial_report` — account statement by CIF.
- **Dual-layer redaction interceptor** — every tool output passes through the
  engine before reaching Claude:
  - **Layer 1 (key-based, stricter):** the field key name decides the masker
    (case-insensitive). Removes the false-positive class where a 16-digit NIK
    accidentally passes the Luhn check and is masked as a credit card.
  - **Layer 2 (fallback, deep text scan):** raw strings / free text / unspecific
    keys fall back to the ordered global regex pipeline.
- **Banking field-level masking** for `cifNumber`, `accountNumber`, `pan`,
  `phoneNumber`, `email`, plus generic `creditCard` / `bankAccount` / `nik`.
- **Numeric safety** — `balance` / `amount` keep their JSON **number** type
  (never turned into `"X"`), so the AI can still reason about them. Under strict
  compliance they are zeroed.
- **Zero-trust block** — a forbidden field (`password`, `pin`, `cvv`, `secret`,
  …) causes the whole response to be blocked; only a safe error reaches Claude.
- **Audit logging** to `audit.log` (JSON Lines): `timestamp`, `tool_called`,
  `user_id_mock`, `status_compliance` (`CLEAN` / `REDACTED` / `BLOCKED`), plus a
  per-category breakdown that records the detection **method** (`KEY_MATCH` /
  `REGEX_MATCH`).
- **SIEM-ready incident logs** — severe breaches and pipeline errors emit a
  single ECS-style JSON line to **stderr** for ELK / Logstash.
- **Strict TypeScript** — `strict` mode, no `any`, no unchecked index access.
- **Unit tested** — 28 tests via the built-in `node:test` runner.

---

## Project structure

```
priva-mcp/
├── src/
│   ├── server.ts            # MCP entry point: pipeline, strict mode, incident logs
│   ├── compliance/          # Dual-layer redaction engine
│   │   ├── types.ts         # SensitiveCategory, JsonValue, CriticalViolation, …
│   │   ├── masking.ts       # pure maskers (card, NIK, CIF, email, phone, …)
│   │   ├── patterns.ts      # KEY_RULES (Layer 1) + regex rules (Layer 2) + forbidden keys
│   │   ├── redactor.ts      # ComplianceEngine (recursive redactObject)
│   │   └── index.ts
│   ├── gateway/             # Proxy logic + mock internal API data
│   │   ├── mockData.ts      # banking records (CIF-keyed)
│   │   ├── gateway.ts       # InternalGateway (returns RAW data)
│   │   └── index.ts
│   └── logs/                # Audit trail
│       ├── auditLogger.ts
│       └── index.ts
├── test/                    # node:test suites
│   ├── masking.test.ts
│   ├── patterns.test.ts
│   └── redactor.test.ts
├── audit.log                # generated at runtime (git-ignored)
├── package.json
├── tsconfig.json
└── README.md
```

---

## Requirements

- Node.js >= 18.18 (developed on Node 22)
- npm

---

## Install

```bash
npm install
```

---

## Run locally

### Development (auto-reload, runs the TS directly)

```bash
npm run dev
```

### Production (compile, then run JS)

```bash
npm run build
npm start
```

The server speaks MCP over **stdio**, so on startup it waits for a client on
stdin/stdout. The only thing printed to your terminal (stderr) is a readiness
line:

```
[priva-mcp] v1.0.0 ready on stdio. strict=true audit=C:\...\priva-mcp\audit.log
```

> Type checking only (no emit): `npm run typecheck`.

---

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `COMPLIANCE_STRICT` | `true` | When `true`, `balance` / `amount` numbers are **zeroed**. Set to `false` to pass amounts through untouched (e.g. when the AI must calculate on real figures). |
| `AUDIT_LOG_PATH` | `<cwd>/audit.log` | Absolute or relative path for the audit trail. |

> Banking default is **strict** (`COMPLIANCE_STRICT=true`) — zero-trust.

---

## Tools & mock data

Both tools take a **CIF number** (`cifNumber`) and an optional `requestedBy`
(recorded in the audit trail as `user_id_mock`).

| Tool | Argument | Returns |
|---|---|---|
| `get_customer_profile` | `cifNumber`, `requestedBy?` | banking profile |
| `get_financial_report` | `cifNumber`, `requestedBy?` | account statement |

Valid mock CIF ids: **`CIF-7782001`**, **`CIF-7782002`**.

Raw (pre-redaction) profile shape returned by the gateway:

```jsonc
{
  "cifNumber": "CIF-7782001",
  "customerName": "Andi Wijaya",
  "accountNumber": "0012345678901",
  "pan": "4111111111111111",
  "phoneNumber": "+6281234567890",
  "email": "andi.wijaya@example.com",
  "balance": 15750000,
  "currency": "IDR",
  "branch": "KCP Sudirman Jakarta"
}
```

What Claude actually receives (strict mode):

```jsonc
{
  "cifNumber": "REDACTED-CIF",
  "customerName": "Andi Wijaya",
  "accountNumber": "XXXXXXXXX8901",
  "pan": "XXXX-XXXX-XXXX-1111",
  "phoneNumber": "+XXXXXXXXXX890",
  "email": "a***a@e***.com",
  "balance": 0,
  "currency": "IDR",
  "branch": "KCP Sudirman Jakarta"
}
```

---

## Redaction reference

### Layer 1 — key-based (field-level)

Key names are normalized (lower-cased, non-alphanumerics stripped) then matched
by substring. Rules are evaluated **in order**; the first match wins.

| Key contains | Category | Mask | Example |
|---|---|---|---|
| `email` | `email` | partial | `andi@example.com` → `a***i@e***.com` |
| `nik`, `id_card`, `identity`, `ktp` | `national_id` | keep last 4 | `3173012501900002` → `XXXXXXXXXXXX0002` |
| `cif` | `cif` | full | `CIF-7782001` → `REDACTED-CIF` |
| `pan`, `card`, `credit` | `credit_card` | Luhn → grouped | `4111111111111111` → `XXXX-XXXX-XXXX-1111` |
| `phone`, `telp`, `mobile`, `msisdn` | `phone` | keep last 3 | `+6281234567890` → `+XXXXXXXXXX890` |
| `bankaccount`, `rekening`, `norekening`, `iban`, `accountnumber`, `virtualaccount` | `bank_account` | keep last 4 | `0012345678901` → `XXXXXXXXX8901` |
| `balance`, `amount` | `financial_amount` | numeric (see below) | `15750000` → `0` (strict) |

Ordering matters: `national_id` is checked **before** `credit_card`, so a key
like `id_card` (which contains the `card` token) is classified as a national ID,
not a card. `cif` is checked before account/card so `cifNumber` is never
mis-handled.

Deliberately specific tokens avoid collisions:
- token is `bankaccount` (not bare `account`) → `accountHolder` (a name) is never
  masked as a bank number;
- there is no bare `id` token → `customerId` is never treated as a NIK.

### Layer 2 — global regex fallback

Applied to raw strings, free text, and fields whose key is not specific. Rules
run in order; once a value is masked its digits become `X` and cannot be
re-matched by a later, broader rule.

| Order | Category | Notes |
|---|---|---|
| 1 | `email` | unambiguous (`@`) |
| 2 | `phone` | Indonesian mobile format |
| 3 | `credit_card` | 13–19 digits, **Luhn-validated** |
| 4 | `national_id` | exactly 16 contiguous digits |
| 5 | `bank_account` | 10–15 contiguous digits |

---

## Strict mode & numeric safety

`balance` / `amount` fields hold numbers the AI may need to compute on, so they
are **never** turned into an `"X"` string (that would corrupt the JSON number
type). Behavior depends on `COMPLIANCE_STRICT`:

| Mode | `balance: 15750000` becomes | Use case |
|---|---|---|
| **strict** (default) | `0` (still a number) | Zero-trust: the figure is protected but the JSON stays valid/parseable. |
| **non-strict** (`COMPLIANCE_STRICT=false`) | `15750000` (unchanged) | The AI must calculate on real figures. |

> Strict mode also zeroes statement `amount` values. That is the intended
> policy; flip the env var per deployment if real numbers are required.

---

## Zero-trust block & ELK incident logging

Some keys must **never** cross the proxy. They are detected by whole-word token
matching (camelCase and separators are split), so `pin` flags `pinCode` / `mPin`
but **not** innocent keys like `shippingAddress`.

Forbidden word-tokens: `password`, `passwd`, `pwd`, `passphrase`, `pin`, `mpin`,
`otp`, `cvv`, `cvc`, `secret`, `privatekey`, `credential`, `credentials`.

When a forbidden field is present, the server:

1. **Blocks the entire response** — it does not mask and forward.
2. Returns a generic, information-free error to Claude (no PII, no field value):
   ```
   Error: response blocked by privacy & compliance policy (a forbidden
   sensitive field was detected). The incident has been logged.
   ```
3. Writes a single **ECS-style JSON incident** to **stderr** for ELK / Logstash.
   The incident logs the offending **key / path / reason — never the secret
   value**:
   ```json
   {"@timestamp":"2026-06-29T19:41:05.782Z","log.level":"error","log.logger":"priva-mcp.compliance","event.kind":"alert","event.category":"intrusion_detection","event.action":"compliance.critical_violation","event.outcome":"blocked","tool":"get_customer_profile","user_id_mock":"attacker-probe","violation_count":1,"violations":[{"path":"$.pin","key":"pin","reason":"forbidden sensitive field present in gateway response"}],"message":"Forbidden sensitive field detected in gateway response; response blocked before reaching the client."}
   ```
4. Records the call in `audit.log` with `status_compliance: "BLOCKED"`.

Unexpected pipeline errors are contained the same way: a generic error to the
client, full detail (incl. `error.stack_trace`) to stderr under
`event.action: "compliance.pipeline_error"`. **stdout never carries a leak.**

> Ingest tip: point Filebeat / Logstash at the process **stderr** stream and
> parse each line as JSON. The fields follow Elastic Common Schema naming
> (`@timestamp`, `log.level`, `event.*`, `error.*`).

---

## Audit log format

`audit.log` is [JSON Lines](https://jsonlines.org/) — one record per call.
Override the location with `AUDIT_LOG_PATH`.

Redacted (normal) call:

```json
{"timestamp":"2026-06-29T19:40:02.026Z","tool_called":"get_customer_profile","user_id_mock":"teller-01","status_compliance":"REDACTED","redactions":[{"category":"cif","method":"KEY_MATCH","count":1},{"category":"bank_account","method":"KEY_MATCH","count":1},{"category":"credit_card","method":"KEY_MATCH","count":1},{"category":"phone","method":"KEY_MATCH","count":1},{"category":"email","method":"KEY_MATCH","count":1},{"category":"financial_amount","method":"KEY_MATCH","count":1}],"total_redactions":6}
```

Blocked call:

```json
{"timestamp":"2026-06-29T19:41:05.784Z","tool_called":"get_customer_profile","user_id_mock":"attacker-probe","status_compliance":"BLOCKED","redactions":[...],"total_redactions":6,"note":"critical violation: pin"}
```

| Field | Meaning |
|---|---|
| `timestamp` | ISO-8601 |
| `tool_called` | tool name |
| `user_id_mock` | requester (`requestedBy`, or `mock-user-001`) |
| `status_compliance` | `CLEAN` \| `REDACTED` \| `BLOCKED` |
| `redactions[]` | `{ category, method, count }` per category |
| `total_redactions` | sum across categories |
| `note` | optional (errors, blocks) |

---

## Quick manual smoke test

Drive the server by hand with a JSON-RPC sequence piped to stdin.

**PowerShell:**

```powershell
$lines = @(
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0.0"}}}'
  '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_customer_profile","arguments":{"cifNumber":"CIF-7782001","requestedBy":"teller-01"}}}'
)
$lines -join "`n" | node dist/server.js
```

**bash:**

```bash
printf '%s\n' \
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0.0"}}}' \
'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_customer_profile","arguments":{"cifNumber":"CIF-7782001","requestedBy":"teller-01"}}}' \
| node dist/server.js
```

You should see the profile returned with sensitive fields masked, `balance: 0`
(strict), and a new `REDACTED` line in `audit.log`. To see amounts preserved,
prefix with `COMPLIANCE_STRICT=false`.

---

## Connect to Claude Desktop

1. Build so `dist/server.js` exists:

   ```bash
   npm run build
   ```

2. Open Claude Desktop config:
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

3. Add Priva-MCP under `mcpServers` (use an **absolute path** to `dist/server.js`):

   ```json
   {
     "mcpServers": {
       "priva-mcp": {
         "command": "node",
         "args": ["C:\\Users\\adhi0\\Projects\\Development\\priva-mcp\\dist\\server.js"],
         "env": {
           "COMPLIANCE_STRICT": "true",
           "AUDIT_LOG_PATH": "C:\\Users\\adhi0\\Projects\\Development\\priva-mcp\\audit.log"
         }
       }
     }
   }
   ```

   > On macOS/Linux use a normal path, e.g. `"/Users/you/priva-mcp/dist/server.js"`.
   >
   > Prefer not to build? Point `command` at `npx` and `args` at
   > `["tsx", "C:\\...\\priva-mcp\\src\\server.ts"]` to run the TypeScript
   > directly (requires `tsx`, a dev dependency).

4. Fully **restart Claude Desktop**. The two tools appear in the tools menu. Ask
   Claude e.g. *"get the profile for CIF-7782001"* and confirm the returned data
   is masked.

---

## Testing

```bash
npm test
```

Uses the built-in `node:test` runner via `tsx` (no extra dependencies). Coverage:

- `masking.ts` — card / keep-last-4 / NIK / CIF / email / phone, plus edge cases.
- `patterns.ts` — Luhn, key normalization, key classification (incl. near-miss
  guards like `customerId` / `accountHolder`), amount-key detection, forbidden
  word-token detection.
- `redactor.ts` — Layer 1 `KEY_MATCH`, Layer 2 `REGEX_MATCH`, NIK false-positive
  fix, banking fields (`cif` / `pan` / `accountNumber`), strict vs non-strict
  numeric handling, and the zero-trust block (with violation path).

---

## How detection works

Rules in `src/compliance/patterns.ts` drive both layers:

- **Layer 1 (`KEY_RULES`)** maps key-name tokens to maskers and runs first for
  any field inside a structured object. This is the precise, high-confidence
  path — it bypasses the blind regex entirely, so a 16-digit NIK in a `nik`
  field can never be mistaken for a credit card.
- **Layer 2 (`REDACTION_RULES`)** is the ordered global regex fallback for raw
  text and unspecific keys. Once a value is masked its digits become `X` and
  cannot be re-matched by a later, broader rule, which lets high-confidence rules
  (email, phone, Luhn-validated cards) run before generic numeric fallbacks.

The recursive `ComplianceEngine.redactObject(input: unknown)` walks objects and
arrays, narrows types at runtime (no unchecked `any`), tracks a JSON path for
incident reporting, and collects both the masked output and any critical
violations.

To add a category: append a `KeyRule` to `KEY_RULES` and/or a `RedactionRule` to
`REDACTION_RULES`. To swap the mock gateway for a real internal API: replace the
methods in `src/gateway/gateway.ts` — the compliance, audit, and incident layers
stay untouched.

---

## Data flow — what reaches Anthropic

The MCP server runs **locally** (Claude Desktop spawns it over stdio). But the
Claude *model* runs on Anthropic's servers, so whatever a tool returns to the
client is included in the conversation context sent to Anthropic. Priva-MCP's job
is to make sure only **masked** data ever crosses that boundary.

```
        ── your machine (local) ─────────────────────┊── Anthropic (cloud) ──
  Internal API ──raw──▶ Priva-MCP ──masked──▶ Claude Desktop ──masked only──▶ Claude model
   (DB/REST)            (mask+block)            (MCP client)   ┊
                            │                                  ┊
                            ▼                                  ┊ trust boundary
                   audit.log + ELK incident  ── stays local 🔒 ┊
```

- **Sent to Anthropic:** the masked tool output (e.g. `REDACTED-CIF`,
  `XXXX-…-1111`, `balance: 0`) plus the prompts you type — the model needs them
  to answer.
- **Never sent:** raw PII (exists only in the local process's RAM), blocked
  forbidden fields, and the `audit.log` / stderr incident logs — all stay on your
  machine.
- **Keep in mind:**
  - A partial mask (e.g. last 4 digits) still leaves the machine; the full
    secret does not.
  - Your own chat messages are **not** scrubbed — Priva-MCP only filters *tool
    output*, not your prompt. Don't paste raw PII directly into chat.
  - With `COMPLIANCE_STRICT=false`, real balances/amounts are sent.
  - Coverage equals rule quality — fields not matched by `KEY_RULES` fall back to
    the Layer 2 regex; what it misses could pass through.
  - Data sent to Anthropic is then subject to Anthropic's own data policy for your
    plan; Priva-MCP minimizes *what* is sent, not its downstream retention.

---

## Landing page (Vercel)

A static landing page lives in [`web/`](web/index.html) — an intro to the project
plus a copy-paste implementation guide. It is plain HTML/CSS/JS (no build step).

Deploy options:

- **Zero-config import:** import the repo into Vercel. The root
  [`vercel.json`](vercel.json) routes `/` to `web/index.html` and serves the rest
  as static assets — no framework or build command needed.
- **Root-directory mode:** alternatively, set Vercel's *Root Directory* to `web`
  and leave the build command empty.
- **Local preview:** `npx serve web` (or open `web/index.html` directly).

---

## Extending toward production

- **Role-based masking** — vary mask depth by the caller's clearance (e.g. a
  fraud analyst may see more than a chatbot).
- **NER for free text** — replace regex heuristics with a dedicated PII model for
  unstructured fields.
- **SIEM transport** — ship audit + incident records over a real transport
  (Kafka / HTTP) instead of files / stderr; the ECS field names already align
  with Elastic.
- **Config-driven policy** — externalize `KEY_RULES`, forbidden words, and strict
  mode into a signed policy file with hot reload.
- **Tokenization / FPE** — replace masking with format-preserving encryption so
  values remain join-able downstream without exposing the plaintext.
```
