# alx

Read-only Rust CLI for Algolia cost investigation and key-abuse forensics at
1000farmacie. It exists to cover the four things Algolia's official CLI
(`algolia/cli`) does not: the **Logs API**, **usage/billing figures**,
**Search Analytics**, and **Insights API forensics** (Events -> Health /
Events -> Debugger). It does not re-implement index, settings, rules, or
synonym management — the official CLI already covers that well.

Command reference for Claude Code and other coding agents: [`CLAUDE.md`](CLAUDE.md).

## What alx is (and isn't)

| Capability | Official `algolia` CLI | `alx` |
|---|---|---|
| Indices, settings, rules, synonyms, crawler | covered | **do not build** |
| API keys + ACLs + restrictions | covered | thin read-only audit wrapper, for scriptable output |
| Logs API (caller IP, Referer, per-request forensics) | absent | **core** |
| Usage / billing (operations, requests, record units) | absent | **core** |
| Search Analytics (top queries, no-result rate) | absent | **core** |
| Insights API (Events -> Health metrics, Events -> Debugger sample) | absent | **core** |

The justification for a *persisted, scheduled* sampler rather than a one-off
script: Algolia's Logs API caps at 1,000 entries per server with a 7-day
retention window, and at this app's request volume that buffer turns over in
minutes. A daily cron job would capture a fraction of a percent of traffic —
by the time a bill arrives, the evidence that would explain it is long gone.
`alx logs sample --persist` exists to lose that race less badly.

## Status

All six command groups are implemented and tested: `doctor` (capability
matrix), `logs sample|offsite|errors` (the 7-day/1,000-entry retention race),
`keys audit` (read-only ACL/restriction audit), `usage summary|series|meters`
(billing meters), `analytics
top-searches|no-results|scrape-signals|clicks|conversions|revenue`
(query-shape heuristics plus click/conversion/revenue metrics), and `events
metrics|sample|errors` (Insights API — Events -> Health / Events ->
Debugger).

## Testing

431 tests, all offline and deterministic — no network, no credentials:

- **Per-criterion suites** (`tests/logs_wiremock.rs`, `tests/usage_*.rs`,
  `tests/doctor_capability_matrix.rs`, …): every acceptance criterion from
  the design workspace maps to a named test (`l1_no_index_name_param`,
  `u1_both_meters_in_summary_json`, `k2_nat_hazard_hard_warning`, …),
  asserted at the HTTP level against wiremock.
- **End-to-end CLI** (`tests/e2e_*.rs`): the compiled binary via `assert_cmd`
  with `env_clear()` — full exit-code matrix (0/1/2/3/4/5/6), JSON envelope
  invariants (`session_ops` everywhere, both usage meters side by side),
  `--human`/`--jq` modes, and redaction sweeps asserting a marker key value
  never appears in stdout+stderr on any failure path.
- **Hostile input** (`tests/hostile_*.rs`): malformed/adversarial wire data —
  non-numeric numeric-strings, 1MB header blobs, CR-only line endings,
  origin-allow-list lookalike attacks, garbage Team Cymru TXT records —
  asserting typed errors, never panics.
- **HTTP contract** (`tests/httpx_*.rs`): 429 retry bounds, plan-gated vs
  missing-ACL fingerprinting, timeout mapping, per-host failure isolation,
  `session_ops` increment semantics under retry, analytics throttle
  serialization.

```bash
cargo test                                    # full suite
cargo clippy --all-targets -- -D warnings     # lint gate (CI-enforced)
cargo fmt --check                             # format gate (CI-enforced)
```

Instrumented line coverage: **72.98%** (`cargo tarpaulin --engine llvm`).
The honest caveat: the e2e suites spawn the binary as a subprocess with a
cleared environment, which strips `LLVM_PROFILE_FILE`, so tarpaulin cannot
see the lines they exercise — `src/commands/logs.rs` and
`src/commands/usage.rs` read as lightly covered while being the most
heavily behaviorally-tested files in the repo. Treat the instrumented
number as a floor, not the behavioral truth.

## Install

```bash
cargo build --release              # -> target/release/alx
make install                       # -> ~/bin (PREFIX=~/.local/bin make install to override)
make uninstall                     # remove from PREFIX
```

`Makefile` has exactly three targets — `build`, `install` (depends on
`build`), `uninstall` — no lint/test/release targets wrapped; run
`cargo test` / `cargo clippy --all-targets -- -D warnings` / `cargo fmt
--check` directly. `PREFIX` defaults to `$HOME/bin`.

```bash
alx completions bash > ~/.local/share/bash-completion/completions/alx
alx completions zsh   > ~/.zsh/completions/_alx
alx manpage > alx.1   # hidden utility subcommand, for packaging
```

## Credentials

Verbatim env-var contract (binding decision D3 of the build):

- Env contract (documented in this order):
  - `ALGOLIA_APPLICATION_ID` — required everywhere (or `--app-id`).
  - Per-surface keys, first match wins per command:
    logs → `ALGOLIA_LOGS_API_KEY`; usage → `ALGOLIA_USAGE_API_KEY`;
    analytics → `ALGOLIA_ANALYTICS_API_KEY`; keys audit → `ALGOLIA_KEYS_API_KEY`;
    events (Insights API) → `ALGOLIA_INSIGHTS_API_KEY`, falling back to
    `ALGOLIA_LOGS_API_KEY` before the generic fallback (the **logs** ACL is
    empirically what the live Insights API accepts — measured 2026-08-04 —
    so no new key needs minting if a logs key is already configured).
    Generic fallback for all: `ALGOLIA_API_KEY`, then `--key` flag (highest priority).
  - NEVER read `ALGOLIA_WRITE_API_KEY` or `ALGOLIA_SEARCH_API_KEY` implicitly.
- **Over-privilege gate (spec §0.3):** before the first real call, best-effort
  self-inspect via `GET /1/keys/{key}` using the key itself (non-admin keys can read
  their own definition). If the ACL set contains any of
  `{addObject, deleteObject, deleteIndex, editSettings, settings}` → refuse with exit
  code 6 unless `--i-know`. If self-inspect fails (403/404/network) → proceed
  without the check (do not block on it), noting in verbose mode only.
- **Redaction:** a key value must never appear in any output, log, error, debug or
  verbose path. When a key must be identified, print `<first 4 chars>…(<len>)`.
  Centralize as `fn mask_key(&str) -> String` in one place; tests assert on it.

Precedence in plain terms, per command: `--key` (the global flag) always wins
if set; otherwise the command's own per-surface env var; otherwise the
generic `ALGOLIA_API_KEY`; otherwise the command fails with a clean
`invalid input` error naming exactly which env var to set. `alx doctor` is
the exception — it tolerates missing credentials per capability and reports
a `no_credentials` row instead of failing.

```bash
export ALGOLIA_APPLICATION_ID=ABC123XYZ
export ALGOLIA_LOGS_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export ALGOLIA_USAGE_API_KEY=yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
export ALGOLIA_ANALYTICS_API_KEY=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
export ALGOLIA_KEYS_API_KEY=wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
```

Minting the keys: in the Algolia dashboard's API Keys screen, create one new
key per surface with **only** the ACL that surface needs (`logs`, `usage`,
`analytics`) — never reuse `ALGOLIA_WRITE_API_KEY` (the app's admin/indexing
key) or `ALGOLIA_SEARCH_API_KEY` (the public browser search key) for
this. Which exact ACL name the Usage API actually requires is unverified in
Algolia's own docs (`usage` per the build spec, `monitoring` per one API
reference) — mint with `usage` first and let `alx doctor` tell you
empirically whether it's reachable; `alx` never hard-fails on an assumed ACL
name.

## Commands

Global flags (apply to every subcommand):

| Flag | Default | Description |
|---|---|---|
| `--json` | off | Output as JSON — already the default; kept as an explicit no-op |
| `--human` | off | Opt into colored human-readable rendering (JSON is the default) |
| `--jq <EXPR>` | none | Pipe the JSON payload through the system `jq` binary |
| `-v, --verbose` | off | Show progress/diagnostic output on stderr |
| `--timeout <SECS>` | `15` | HTTP timeout in seconds |
| `--agent` | off (auto-detected) | Force agent mode (machine-friendly JSON output) |
| `--i-know` | off | Acknowledge and proceed despite an over-privileged key |
| `--app-id <ID>` | env | Algolia Application ID (overrides `ALGOLIA_APPLICATION_ID`) |
| `--key <KEY>` | env | Algolia API key (highest priority; overrides every `ALGOLIA_*_API_KEY`) |

### `alx doctor` — capability matrix

Probes `logs`/`usage`/`analytics`/`keys`/`insights` reachability and reports a matrix,
never a raw 403. Runs with whatever credentials exist — a missing env var is
a `no_credentials` row, not a failure; `doctor` only fails if
`ALGOLIA_APPLICATION_ID`/`--app-id` is entirely absent.

```bash
alx doctor
alx doctor --human
alx doctor --jq '.capabilities[] | select(.reachable == false)'
```

### `alx logs sample|offsite|errors` — the 7-day/1,000-entry retention race

Fans out concurrently across the three per-server hosts
(`{app}-1|2|3.algolianet.com`), merges + dedupes on `(sha1, timestamp, ip)`,
and applies `--since` as a client-side filter after fetch.

```bash
# Sample the last 2 hours, write durable evidence to disk
alx logs sample --since 2h --persist ./algolia-logs/

# Group non-own-egress, non-KEEP-list traffic by (ip, referer)
alx logs offsite --since 6h

# Non-200 answer_code entries — catches referer-allow-list rejections
alx logs errors --since 24h
```

| Flag | Description |
|---|---|
| `--since <Nm\|Nh\|Nd>` | Sampling window applied client-side after fetch (default `1h`) |
| `--persist <DIR>` | (`sample` only) Write the aggregated sample to disk; never overwrites — collisions get `-2`, `-3`, ... suffixes |

`--persist` writes one `alx-logs-<UTC ts>-<host>.jsonl` per contributing
host plus one `alx-logs-<ts>-meta.json` describing the window/counts —
running it twice never clobbers prior evidence, even from two concurrent
invocations landing in the same second.

### `alx keys audit` — read-only ACL/restriction audit

```bash
alx keys audit
# Flag a key as a hard NAT-hazard warning if it's also used server-side
alx keys audit --server-side-key serversidekeyprefix
ALX_SERVER_SIDE_KEYS=prefix1,prefix2 alx keys audit
```

| Flag | Description |
|---|---|
| `--server-side-key <PREFIX>` | Masked-prefix or description of a key known to also be used server-side (repeatable; also read from `ALX_SERVER_SIDE_KEYS`, comma-separated) |

Two hard-coded checks: **K1** warns when a browser-scoped key is missing
one of the four frontend indexes (`Product`, `QuerySuggestions`, `Category`,
`Brand`); **K2** warns when a rate-limited key is also used server-side (a
NAT hazard — server-side callers usually egress through a handful of NAT
IPs, so a browser-sized `maxQueriesPerIPPerHour` can throttle all of them at
once, with no deploy and no rollback signal). Algolia's key metadata cannot
say whether a key is used server-side, so K2 is a hard warning only for keys
you name with `--server-side-key`; otherwise it is an advisory.

### `alx usage summary|series|meters` — billing meters

Requires a key with the Usage API's ACL; only useful once `alx doctor`
reports `usage` as reachable (Premium/Enterprise plan add-on).

```bash
# Both meters side by side, plus the derived billed-requests approximation
alx usage summary --since 30d

# Raw daily time series for one statistic
alx usage series --statistic total_search_operations --granularity daily --since 90d

# Dedicated requests-vs-operations side-by-side daily view
alx usage meters --since 14d
```

| Flag | Description |
|---|---|
| `--since <Nm\|Nh\|Nd>` | Lookback window (default `30d`) |
| `--statistic <NAME>` | (`series` only, required) e.g. `total_search_requests`, `total_search_operations`, `records`, `indexing_operations`, `storage` |
| `--granularity <hourly\|daily>` | (`series` only, required) `hourly` supports ≤7 days, `daily` supports ≤365 days — rejected before any HTTP call if the window is too wide |

### `alx analytics top-searches|no-results|scrape-signals|clicks|conversions|revenue` — Search Analytics

```bash
alx analytics top-searches --since 30d --limit 50
alx analytics no-results --since 30d --region us
alx analytics scrape-signals --since 30d
alx analytics clicks --since 30d
alx analytics conversions --since 30d --region us
alx analytics revenue --since 30d
```

| Flag | Description |
|---|---|
| `--since <Nm\|Nh\|Nd>` | Lookback window (default `30d`) |
| `--limit <N>` | (`top-searches`/`no-results` only) Max rows to return |
| `--region <de\|us>` | Analytics region (default `de` — our app is EU; a 404 gets a suggestion to retry the other region, since Algolia doesn't distinguish "wrong region" from "index not found") |

All six read against `Product`, the frontend's primary search index — no
`--index` flag exists (the design deliberately keeps this to one documented
default). `no-results` always fetches the overall `noResultRate` alongside
the row list — it never shows the list without the headline rate.
`scrape-signals` fires four independently-reported heuristics (systematic
enumeration, empty-query high-volume pagination, non-served-language/test
strings, flat query distribution) — see [Hard limitations](#hard-limitations)
for why every signal is worded as "suspicious pattern", never "confirmed".

`clicks`, `conversions`, and `revenue` wrap the click/conversion/revenue
endpoints of the Analytics API (`/2/clicks/*`, `/2/conversions/*`):

- **`clicks`** — click-through rate + average click position + the click
  position histogram (`[start, end]` buckets, where `end == -1` means
  "unbounded", rendered as e.g. `21+`), in one payload.
- **`conversions`** — conversion rate, add-to-cart rate, and purchase rate,
  side by side (same "never show one meter alone" discipline as `usage
  summary`'s requests/operations pairing).
- **`revenue`** — the `currencies` map flattened to one row per currency.
  Never assumes EUR: whatever currencies Algolia's `revenue` response
  actually contains are rendered, unhardcoded.

Every one of the three also surfaces `/2/status`'s `updatedAt` freshness
timestamp (`updated_at` in JSON) — a post-deploy re-measurement is
worthless if the analytics data hasn't refreshed yet, so it rides along on
every response rather than requiring a separate `alx doctor` check. Each
command fires its calls (four for `clicks`/`conversions`, two for
`revenue`) sequentially through the same shared A1 throttle as
`no-results` — never concurrently.

### `alx events metrics|sample|errors` — Insights API (Events -> Health / Events -> Debugger)

Wraps the same public REST API that backs the Algolia dashboard's Events
screens — discovered 2026-08-04 by watching its network traffic. Region is
hardcoded to `de` (this app's Insights traffic lives there; `us` 401s
outright — a different failure class than the analytics API's empty-region
200, see [Rate limits](#rate-limits)) — there is no `--region` flag.

```bash
# Events -> Health: totals + per-bucket series (eventCount, errorCount/errorRate, ...)
alx events metrics --since 30d --granularity day

# Events -> Debugger: aggregated sample of the live rolling event buffer
alx events sample --since 10m --persist ./algolia-events/

# Same fetch, filtered + grouped to ingest failures
alx events errors --since 10m
```

| Flag | Applies to | Description |
|---|---|---|
| `--since <Nm\|Nh\|Nd>` | all three | Lookback window (`metrics` default `30d`; `sample`/`errors` default `10m`) |
| `--granularity <hour\|day>` | `metrics` only | Bucket size — `week` is not offered (the live API returns HTTP 422 for it; rejected client-side by construction, the CLI enum has no `week` variant) |
| `--approximate <true\|false>` | `metrics` only | Include near-real-time (not-yet-finalized) counts (default `true`; differs from `false` by ~8 events across a measured 3-day window — negligible, exposed rather than hidden) |
| `--limit <N>` | `sample` only | Cap the number of events fetched — **truncates only**, there is no pagination (`offset`/`page`/`length` all return 0 events, verified live) |
| `--persist <DIR>` | `sample` only | Write the raw events (jsonl) + `meta.json` to disk; same never-overwrite / `-2`, `-3`, ... suffix contract as `logs sample --persist` |

**`/1/events` is a rolling buffer of roughly 3,000 events, NOT a
time-windowed query.** Measured 2026-08-04: a 10-minute, 1-hour, 1-day, and
30-day window ALL returned the same ~2,990-2,997 most-recent events — the
buffer, not the requested `--since`. At a few hundred events per minute
that's a turnover of **a few minutes**, and it gets *shorter* as traffic grows.
`sample`/`errors` report the observed buffer span exactly like `logs
sample`'s `window.elapsed_minutes` does — that number is the operator's
*required* sampling interval, not a stat to skim past — and both flag
`"truncated": true` with an explicit warning whenever the fetch lands at or
near the cap, so older, silently-dropped events are never presented as a
complete picture of the requested window.

`sample` aggregates rather than dumping the raw stream (unreadable at
~3,000 rows): by `eventName`, `eventType`/`eventSubtype`, `algoliaSource`
(identifies the emitting library — `instantsearch`, `autocomplete`, or
absent for server-side/hand-rolled emitters), `client` (derived from
`User-Agent`: browser / Hotwire Native Android / Hotwire Native iOS /
server-side Ruby / other), ingest status, and error message. `queryID`
presence is broken down **per `eventType`** — a view event correctly never
carries one, so one blended percentage across all types would be
misleading. `errors` groups failing events by `(error message, eventName,
algoliaSource, client)` — that table IS the "error class -> emitting
component -> cause" view.

## Output modes

JSON is the **default** output mode — this differs from algosearch, which
defaults to human-readable text. `--human` opts into colored rendering;
`--jq <EXPR>` pipes the final JSON payload through the *system* `jq` binary
(a missing `jq` on `PATH` is a clean error, never a silent JSON dump). LLM
agent detection (see [Agent mode](#agent-mode)) always forces JSON, even
over an explicit `--human`.

```bash
alx doctor --jq '.capabilities | map(select(.reachable))'
alx logs offsite --since 24h --jq '.offsite[0:5]'
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | generic/unexpected error |
| 2 | clap usage error (bad flags/args — clap's own exit code) |
| 3 | network/timeout |
| 4 | auth: invalid key / missing ACL |
| 5 | plan-gated capability (Usage/Analytics not included in the plan) |
| 6 | safety refusal — the configured key carries a write ACL and `--i-know` was not passed |

## Quota honesty

Every `logs`/`usage`/`analytics`/`keys`/`insights` API call `alx` makes
consumes Algolia's operations quota — and a `logs`/`insights` call itself
never appears in the logs, so there is no way to see this cost from
Algolia's side. Every response envelope embeds a `session_ops` object
counting calls made this session, broken out per surface:

```json
"session_ops": { "logs_calls": 3, "usage_calls": 0, "analytics_calls": 0, "keys_calls": 1, "insights_calls": 0 }
```

Human mode prints the same thing as a closing line:
`session ops — logs: 3, usage: 0, analytics: 0, keys: 1, insights: 0`.

## The two meters — requests vs operations

Algolia bills (and its Usage API reports) two distinct meters that are easy
to conflate, with wrong conclusions as the result.
**Never treat them as interchangeable:**

- **Search Request** — one atomic engine call. A `multipleQueries` batch
  counts as exactly one request, regardless of how many indices it touches.
- **Search Operation** — one sub-query *within* a request. A batch querying
  N indices in one call is 1 request but N operations.

Algolia's own worked example: search-as-you-type typing a 4-character term,
querying 2 indices per keystroke, is **4 requests but 8 operations**. Which
one a given billing tier actually meters changes which optimization pays
off — collapsing them into one "usage" number hides that.

`alx usage summary` and `alx usage meters` print both, always, side by
side — there is no truncated/quick-summary code path that shows only one.
`summary` additionally exposes a first-class derived field:

```
billed_search_requests_approx = total_search_requests − querysuggestions_total_search_requests
```

labeled `derived/approximate` in the response — a computed estimate, never
a value Algolia reports directly.

## Rate limits

| Surface | Limit | `alx` behavior |
|---|---|---|
| Logs | ≤1,000 entries per server; 7-day retention; `offset+length` cannot page past 1,000; each logs call itself consumes operations quota and never shows up in the logs | Fetches once per host per invocation (no pagination attempted past the cap); the shared HTTP layer retries any `429` with exponential backoff (1s/2s/4s, max 3 attempts) |
| Usage | Plan-gated (Premium/Enterprise add-on); exact rate limit undocumented by Algolia | Backs off conservatively via the same universal 429 retry; `doctor` and every usage command classify a `402`/plan-worded `403` as `plan_gated` distinctly from a missing-ACL `401`/`403` |
| Analytics | 100 requests/minute per application | A shared, reservation-based client-side throttle enforces ≥600ms between every analytics call *before* firing it (not just reactive backoff) — a multi-call command like `no-results` (list + overall rate) can never burst past the limit |
| Insights `/1/events` | **A rolling ~3,000-event buffer, NOT a time-windowed query** — every window (10m through 30d) returns the same most-recent ~2,990-2,997 events; `offset`/`page`/`length` are unsupported (all return 0), so there is **no pagination workaround** | `events sample`/`events errors` report the observed buffer's oldest/newest `receivedAt` and the derived required-sampling-interval (mirrors `logs sample`'s window reporting), and flag `"truncated": true` with an explicit warning whenever the fetch lands at/near the cap |
| Insights `/1/metrics` `granularity` | Only `hour`/`day` — `week` measured live -> HTTP 422 | Rejected client-side: the CLI's `--granularity` enum has no `week` variant, and `algolia::insights::validate_metrics_granularity` re-checks it defensively before every fetch |
| Insights region | `insights.us.algolia.io` -> 401 (an **auth failure**, not the analytics API's empty-region 200) | Hardcoded to `de` for every `events` command — no `--region` flag |
| Per-key usage attribution | **Does not exist** — Algolia's finest granularity is application/index/operation-type | `alx` never claims otherwise anywhere in its output or docs — see below |

## Hard limitations

**`alx` cannot and does not attribute Algolia spend to an individual API
key**, anywhere in its output or docs. Algolia's Usage API and Search
Analytics both report at application/index/operation-type granularity —
there is no key dimension to query, so any tool claiming "usage by key" is
guessing. `alx keys audit` audits ACLs and restrictions, never spend.

The honest substitutes, both imperfect:

1. **Separate purpose-scoped keys + `alx logs` sampling.** Mint one key per
   calling surface (this is exactly what the credential contract above
   already does), then use `alx logs sample --persist` to see per-`(ip,
   referer)` call patterns over a persisted window. This tells you *who* is
   calling, sampled, not a complete accounting of *how much*.
2. **The Datadog RUM `algolia.net` resource-count delta.** Cross-referencing
   RUM's resource-timing data against `algolia.net` calls gives an
   approximate per-surface split from the browser side.

`alx analytics scrape-signals` carries the same honesty discipline: every
heuristic (systematic enumeration, empty-query pagination, non-served-
language/test strings, flat distribution) is reported as an independently-
fired "suspicious pattern", never as a confirmed finding — it is explicitly
the least certain part of the design (built last, per the spec's build
order).

## Agent mode

`alx` auto-detects when it's being driven by an LLM coding agent, layered
by confidence (first match wins):

1. Explicit `--agent` flag.
2. Known agent env vars: `CLAUDE_CODE`, `CURSOR_SESSION`, `CODEX`,
   `CONTINUE_SESSION`, `AIDER_SESSION` (any value), or `LLM_AGENT=1`.
3. `CI=true` combined with no TTY on stdin.
4. A walk up to 10 parent processes looking for a name containing `claude`,
   `cursor`, `codex`, `aider`, or `continue`.
5. stdin is not a TTY and `--json` was not explicitly passed.

Because JSON is already `alx`'s default output mode, agent detection's only
visible effect is forcing JSON even over an explicit `--human` — a wrapper
script that happens to pass `--human` can never accidentally hand an agent
colored text.

## Future work

Out of scope for v0.1 (binding decision D13) — noted here rather than left
implicit:

- No usage per-index breakdown command.
- No IPv6 ASN resolution (`logs offsite`'s ASN classification skips IPv6
  entries entirely, tagging them `asn_unknown`).
- No `--asn-db` embedded MaxMind/mmdb backend — ASN resolution is Team
  Cymru origin-DNS lookups only (see `CLAUDE.md`'s gotchas).
- No config file — env vars and flags only, by design (stateless tool).
- No registry/cache — nothing persists between invocations except what
  `--persist` explicitly writes.
- No release automation beyond the GitHub Actions workflow files already
  present (`.github/workflows/`).
