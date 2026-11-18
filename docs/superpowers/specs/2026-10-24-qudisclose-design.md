# qudisclose — machine-to-machine coordinated vulnerability disclosure

Date: 2026-10-24. Status: approved by builder's own judgement (user asked for the
system autonomously; every "how it gets made" choice below is the builder's call
and is marked as such).

## Intent

Traditional coordinated vulnerability disclosure (CVD) is a human workflow: a
researcher emails security@, a maintainer reads it days later, triage happens in
a thread, a fix lands weeks later, an advisory is written by hand, and nobody
writes a postmortem. For a solo or small open-source maintainer the latency is
the vulnerability window.

qudisclose replaces that workflow with a purely machine-to-machine loop over the
Model Context Protocol (MCP):

- researchers' agents (or scanners) submit reports to a hardened MCP intake
  server, or the server pulls reports from the places they already appear;
- a multi-agent team (triage, reproduce, patch, review, release) acts on every
  report **immediately and in parallel**, instead of waiting for a human and a
  90-day embargo clock;
- a postmortem agent writes a blameless review after every case (and after every
  missed SLO) so the maintainer gets a "mini SRE team" view of what went well
  and badly;
- every control the NSA's May 2026 Cybersecurity Information Sheet on MCP
  (*Model Context Protocol (MCP): Security Design Considerations for AI-Driven
  Automation*, U/OO/6030316-26, PP-26-1834) calls for is implemented in code,
  not left to deployment notes.

## Goals

1. Zero-human-in-the-loop path from report to merged patch and published
   advisory, with humans able to pause or veto through the same MCP surface.
2. Speed as the primary SLO. Default targets (configurable): acknowledge in
   15 minutes, triage in 60 minutes, candidate patch for critical/high in
   4 hours, advisory published when the patch ships. Embargo is short by
   default (7 days max) and ends early when a fix is released.
3. Ingest from the sources where vulnerability reports already arrive for OSS:
   GitHub private vulnerability reports and advisories, Dependabot alerts,
   OSV.dev, generic signed webhooks (huntr, HackerOne, Intigriti, fuzzers), and
   direct MCP submission by reporter agents.
4. NSA MCP guidance implemented as code (see "Security controls").
5. Automated, blameless postmortems with quantitative timeline metrics.
6. Runs offline for tests and demos (scripted model provider), and with Claude
   for real.

## Non-goals

- A web UI. Everything is MCP tools/resources plus a CLI.
- Replacing GitHub as the place the code lives. qudisclose opens PRs and
  publishes advisories through GitHub; it does not host repos.
- Being a general bug tracker. Non-security reports are triaged out.
- Multi-tenant SaaS. One deployment serves one maintainer/org.

## Anti-goals (would make it a failure even if it "works")

- Shipping a wrong or incomplete patch fast. The reviewer agent is adversarial
  and independent, and a patch never merges without a passing reproduction test.
- Leaking an embargoed report (via logs, advisory drafts, LLM prompts to third
  parties). Reports are classified; the scanner redacts secrets before anything
  is logged or sent.
- An agent holding long-lived credentials. All credentials are brokered,
  short-lived, task-scoped leases.
- Silent failures. Every missed SLO or failed stage produces a postmortem.

## How it gets made (builder's calls)

- Python 3.13, `uv` project. Packages: `mcp>=2` (official MCP SDK, v2 API:
  `MCPServer`, `Client`, streamable HTTP), `anthropic>=2` (Claude API, tool
  runner), `pydantic`, `cryptography` (Ed25519), `PyJWT`, `uvicorn`, `pytest`.
- SQLite via the standard library for all state (reports, events, audit chain,
  postmortems). Single-file deployment.
- Default model `claude-opus-5-5` with adaptive thinking and server-side
  refusal fallbacks (`fallbacks: "default"`). Effort per agent role. A
  `ScriptedProvider` substitutes for tests/demos so no API key is needed.
- Patch work happens in a sandboxed git worktree subprocess (env scrubbed,
  network disabled where the OS allows, rlimits applied). Container-per-server
  is the recommended production isolation and is documented, not enforced.

## Architecture

```
 reporters' agents ──MCP (signed, scoped)──▶ ┌────────────────────┐
 GitHub PVR / GHSA ─┐                        │  qudisclose intake │
 Dependabot ────────┤  ingest adapters ─────▶ │  MCP server        │──▶ store (sqlite)
 OSV.dev ───────────┤                        │  (NSA controls)    │        │
 signed webhooks ───┘                        └────────────────────┘        ▼
                                                                 ┌──────────────────┐
                                                                 │ orchestrator     │
                                                                 │ (SLO clock)      │
                                                                 └──────────────────┘
                     ┌──────────┬─────────────┬──────────┬───────────┬──────────────┐
                     ▼          ▼             ▼          ▼           ▼              ▼
                  triage   reproducer      patcher   reviewer    release      postmortem
                  agent    agent (sbx)     agent(sbx) agent      agent        agent
```

### Report model

One normalized `Report`: id, source, reporter identity (non-human identity
string + public key if MCP), title, description, affected package/repo,
affected versions, proof-of-concept, suggested CWE/CVSS, embargo deadline,
classification (`embargoed` | `public`), status, timeline events.

### Intake MCP server (`qudisclose.server`)

Streamable HTTP, bearer-token auth (JWT, Ed25519-signed by the deployment's
issuer key). Tools, each with an explicit required scope and MCP
`ToolAnnotations`:

| tool | scope | annotations |
|---|---|---|
| `submit_report` | `report:submit` | non-readonly, non-destructive, idempotent (by content hash) |
| `get_report_status` | `report:read` | readOnly |
| `list_reports` | `report:read` | readOnly |
| `acknowledge_report` | `triage:write` | idempotent |
| `set_embargo` | `triage:write` | |
| `pause_case` / `resume_case` | `admin` | human veto path |
| `get_advisory` | `report:read` | readOnly |
| `get_postmortem` | `report:read` | readOnly |
| `catalog_fingerprint` | none | readOnly; returns the pinned tool-catalog hash |

Resources: `qudisclose://policy` (disclosure policy as JSON),
`qudisclose://reports/{id}`, `qudisclose://advisories/{id}`,
`qudisclose://postmortems/{id}`.

### Ingest adapters (`qudisclose.ingest`)

Protocol `Source.poll() -> list[Report]`. Implementations: `GitHubAdvisories`
(private vulnerability reports + repo advisories), `Dependabot`, `OSV`,
`SignedWebhook` (HMAC-verified JSON), and the MCP `submit_report` tool itself.
Each adapter dedups by `(source, external_id)` and by content hash.

### Agents (`qudisclose.agents`)

All agents share one `Provider` interface (`AnthropicProvider` /
`ScriptedProvider`) and return pydantic-validated structured outputs. Roles:

- **Triage**: is it a vulnerability, severity (CVSS 4.0 vector + score), CWE,
  exploitability, lane (`hotfix` | `scheduled` | `reject`), dedup.
- **Reproducer**: writes a failing test from the PoC in the sandbox; must fail
  on the vulnerable tree.
- **Patcher**: proposes a minimal diff; sandbox runs the reproduction test and
  the project's test suite; iterates up to N times.
- **Reviewer**: a fresh context that sees only the report, the diff and the test
  results — never the patcher's reasoning. Looks for incomplete fixes,
  regressions, scope creep, suspicious additions. Verdict is binding.
- **Release**: version bump, changelog, OSV-format advisory, PR body, CVE
  request text (GitHub CNA via GHSA), publication when merged.
- **Postmortem**: reads the full event timeline and audit chain, computes
  time-to-ack/triage/patch/release against SLOs, writes what went well, what
  went badly, and action items. Also runs when a case fails or an SLO is
  missed.

### Orchestrator (`qudisclose.orchestrator`)

A state machine: `received → acknowledged → triaging → reproducing ∥ patching
→ reviewing → releasing → published → closed`, with `paused` and `rejected`.
Reproduction and patching start **the moment a report is acknowledged**, in
parallel with triage (speculative). A human `pause_case` call halts the
pipeline at the next stage boundary. SLO deadlines are computed at intake and
checked at every transition; a breach is recorded as an event and forces a
postmortem even on success.

### Security controls (NSA CSI mapping) — `qudisclose.security`

| NSA design consideration | Implementation |
|---|---|
| Per-message cryptographic integrity beyond TLS | `SignedEnvelope`: Ed25519 signature over canonical JSON of `{tool, args, nonce, iat, exp, sender}` carried in MCP `_meta`; server middleware verifies, rejects expired or replayed nonces |
| Least privilege at the tool-call boundary, no ambient authority | Every tool declares a required scope; JWT scopes checked per call; agents receive task-scoped `CredentialLease`s from a `CredentialBroker` (short TTL, single repo, single purpose) |
| Distinct non-human identities | Each agent and each reporter has its own key pair / `client_id`; rate limits and revocation are per identity |
| Tamper-evident audit | `AuditLog`: hash-chained, Ed25519-signed entries recording tool inputs **and outputs**, stored in SQLite; `verify_chain()` |
| Tool inventory pinning / rug-pull protection | `catalog_fingerprint()`: SHA-256 over sorted (name, description, schema); clients refuse to call if the live catalog differs from their pin |
| Trust chain / gateway as trust boundary | Server publishes its identity key; clients pin it; server verifies the issuer of every token |
| Tool output as untrusted input, injection detection | `InjectionScanner` flags instruction-like patterns in report bodies and tool outputs; untrusted text is wrapped in a delimited data envelope before it reaches a model |
| Serialization risk / strict validation | Every tool input is a strict pydantic model (`extra="forbid"`), size-capped |
| Sandboxing per execution | `Sandbox`: git worktree, scrubbed env, rlimits, no network (platform permitting), timeouts |
| DLP / egress | `Redactor` strips secrets (tokens, keys, emails) from anything logged or sent to a model; outbound HTTP limited to an allowlist |
| Rate limiting | Token-bucket per identity in the server middleware |
| Human-in-the-loop for sensitive operations | `pause_case` / `resume_case` admin tools; merge and publish are the only two steps that can be configured to require a human lease |

## What's left to the builder

- Exact prompts for each agent.
- SQLite schema details.
- CLI ergonomics.
- The demo fixture: a tiny vulnerable Python package with a path-traversal bug.
