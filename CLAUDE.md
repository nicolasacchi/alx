# CLAUDE.md — alx

Read-only Rust CLI for Algolia cost & abuse forensics at 1000farmacie
(`doctor`, `logs sample|offsite|errors`, `keys audit`, `usage
summary|series|meters`, `analytics
top-searches|no-results|scrape-signals|clicks|conversions|revenue`, `events
metrics|sample|errors`).
Structurally incapable of mutating Algolia state — `src/http.rs` exposes
only a GET executor, no generic request builder taking a method, no
`.post(`/`.put(`/`.delete(`/`Method::POST` anywhere in the codebase outside
tests. Covers the four things Algolia's official `algolia` CLI does not:
Logs API forensics, Usage API billing meters, Search Analytics, and Insights
API forensics (Events -> Health / Events -> Debugger) — see `README.md`
for the full official-CLI gap table and design rationale.

## Read-only by construction

No index mutation, no key creation, no settings changes, no `clear`/
`delete` — anywhere. Reviewer-verifiable: `grep -rn '\.post(\|\.put(\|\.delete(\|Method::POST'
src/` should return nothing outside `tests/`. If a write is ever needed, use
the official `algolia` CLI deliberately — that boundary is intentional, not
an oversight.

## Agent Mode

Auto-detects Claude Code (and other coding agents) via `CLAUDE_CODE` env var,
parent-process-name walk (up to 10 levels), `CI=true`+no-TTY, or stdin not a
TTY. Layered by confidence, first match wins — see `src/agent.rs`. Can also
be forced with `--agent`, or JSON forced explicitly with `--json`. Because
JSON is already the default output mode, agent detection's only visible
effect is overriding an explicit `--human` back to JSON.

## Global Flags

| Flag | Default | Description |
|---|---|---|
| `--json` | off | Force JSON output (already the default; explicit no-op) |
| `--human` | off | Opt into colored human-readable rendering |
| `--jq <EXPR>` | none | Pipe the JSON payload through the system `jq` binary |
| `-v, --verbose` | off | Show progress/diagnostic output on stderr (the only sanctioned incidental-output channel — no raw `eprintln!`/`println!` elsewhere) |
| `--timeout <SECS>` | `15` | HTTP timeout in seconds |
| `--agent` | off (auto-detected) | Force agent mode (machine-friendly JSON) |
| `--i-know` | off | Bypass the over-privileged-key safety refusal |
| `--app-id <ID>` | env | Overrides `ALGOLIA_APPLICATION_ID` |
| `--key <KEY>` | env | Overrides every `ALGOLIA_*_API_KEY` (highest priority) |

## Commands

### doctor — capability matrix

```bash
alx doctor
alx doctor --human
alx doctor --jq '.capabilities[] | select(.reason == "plan_gated")'
```

Probes `logs` (GET `/1/logs?length=1`), `usage` (GET
`usage.algolia.com/1/usage/records`, 1-day window), `analytics` (GET
`analytics.de.algolia.com/2/status`), `keys` (GET `/1/keys`, falling
back to `GET /1/keys/{self}` on 403), and `insights` (GET
`insights.de.algolia.io/1/events?limit=1`, 60-minute window — irrelevant to
the result either way since the live buffer is what comes back regardless).
Runs with whatever credentials exist —
missing env var is a `no_credentials` row, not a hard failure; only fails if
`ALGOLIA_APPLICATION_ID`/`--app-id` is entirely absent. Deliberately skips
the over-privilege preflight (`safety::preflight_privilege_check`) — its
whole job is reporting on whatever key is configured, including
over-privileged ones.

### logs sample|offsite|errors — the 7-day/1,000-entry retention race

```bash
alx logs sample --since 2h --persist ./algolia-logs/
alx logs offsite --since 6h
alx logs errors --since 24h
```

| Flag | Applies to | Description |
|---|---|---|
| `--since <Nm\|Nh\|Nd>` | all three | Client-side filter after fetch (default `1h`) |
| `--persist <DIR>` | `sample` only | Write the aggregated sample to disk; atomic claim via `O_CREAT\|O_EXCL`, never clobbers — collisions suffix `-2`, `-3`, ... |

Fans out concurrently across `{app}-1|2|3.algolianet.com`, `indexName`
**never** sent as a query param (client-side filtering only), `type=all`
always (so referer-rejected/non-200 entries surface). Merges + dedupes on
`(sha1, timestamp, ip)`. `offsite` groups by `(ip, referer)` into six
buckets: `offsite`, `own_egress`, `keep_benign`, `crawler`,
`private_relay_probable`, `asn_unknown`.

### keys audit — read-only ACL/restriction audit

```bash
alx keys audit
alx keys audit --server-side-key serversidekeyprefix
ALX_SERVER_SIDE_KEYS=prefix1,prefix2 alx keys audit
```

| Flag | Description |
|---|---|
| `--server-side-key <PREFIX>` | Masked-prefix/description of a key also used server-side (repeatable; also `ALX_SERVER_SIDE_KEYS`, comma-separated) |

`GET /1/keys`, falling back to `GET /1/keys/{self}` on 403 (marks the audit
`single_key_scoped`). No PUT/POST/DELETE anywhere in `src/algolia/keys.rs`
or `src/commands/keys.rs` — this command cannot mutate by construction (K3).
K1/K2 checks below.

### usage summary|series|meters — billing meters

```bash
alx usage summary --since 30d
alx usage series --statistic total_search_operations --granularity daily --since 90d
alx usage meters --since 14d
```

| Flag | Applies to | Description |
|---|---|---|
| `--since <Nm\|Nh\|Nd>` | all three | Lookback window (default `30d`) |
| `--statistic <NAME>` | `series` (required) | e.g. `total_search_requests`, `total_search_operations`, `querysuggestions_total_search_requests`, `records`, `indexing_operations`, `indexing_requests`, `storage`, `ai_requests` — unknown names pass through with a warning, never rejected |
| `--granularity <hourly\|daily>` | `series` (required) | `hourly` ≤7d, `daily` ≤365d — pre-flight rejected before any HTTP call if the window is too wide |

`summary`/`meters` always print `requests` and `operations` side by side —
no code path shows only one. `summary` also computes
`billed_search_requests_approx = total_search_requests -
querysuggestions_total_search_requests`, labeled `derived/approximate`.

### analytics top-searches|no-results|scrape-signals|clicks|conversions|revenue

```bash
alx analytics top-searches --since 30d --limit 50
alx analytics no-results --since 30d --region us
alx analytics scrape-signals --since 30d
alx analytics clicks --since 30d        # CTR + avg click position + position histogram
alx analytics conversions --since 30d   # conversion / add-to-cart / purchase rates
alx analytics revenue --since 30d       # revenue, AOV, transactions, per currency
```

| Flag | Applies to | Description |
|---|---|---|
| `--since <Nm\|Nh\|Nd>` | all six | Lookback window (default `30d`) |
| `--limit <N>` | `top-searches`/`no-results` | Max rows |
| `--region <de\|us>` | all six | Default `de` (app is EU); 404 gets a "try the other region" suggestion — Algolia doesn't distinguish wrong-region from missing-index |

Always queries `Product` (frontend's primary index) — no `--index` flag.
`no-results` always fetches `noResultRate` alongside the row list. Every
analytics call goes through a shared, reservation-based throttle enforcing
≥600ms between calls (100 req/min cap) — enforced proactively, not just on
429. `scrape-signals` fires four independently-reported heuristics
(`systematic_enumeration`, `empty_query_high_volume_pagination`,
`non_served_language_or_test_strings`, `flat_distribution`) — worded as
"suspicious pattern", never "confirmed".

`clicks`/`conversions`/`revenue` each also fetch `/2/status` and surface its
`updatedAt` as a **data-freshness stamp** — a post-deploy re-measurement is
worthless if the analytics data hasn't refreshed yet, so every payload says
when it was last refreshed. `updatedAt` is `null` for a region/index with no
analytics data (e.g. `--region us` on this app), and that renders as "no data
yet", never an error. `revenue` returns one row per currency read from each
entry's own `currency` field — it never assumes EUR. These three share the
same throttle as the rest of the group, so `clicks` (4 calls) can't burst.

### events metrics|sample|errors — Insights API (Events -> Health / Events -> Debugger)

```bash
alx events metrics --since 30d --granularity day --approximate false
alx events sample --since 10m --persist ./algolia-events/
alx events errors --since 10m
```

| Flag | Applies to | Description |
|---|---|---|
| `--since <Nm\|Nh\|Nd>` | all three | `metrics` default `30d`; `sample`/`errors` default `10m` (cosmetic for the latter two — see buffer gotcha below) |
| `--granularity <hour\|day>` | `metrics` | `week` not offered — the CLI enum has only hour/day, `week` measured HTTP 422 live |
| `--approximate <true\|false>` | `metrics` | Default `true`; ~8-event difference across a measured 3-day window |
| `--limit <N>` | `sample` | Truncates only — no pagination exists (`offset`/`page`/`length` all return 0, verified live) |
| `--persist <DIR>` | `sample` | Same never-overwrite / `-2`/`-3`-suffix contract as `logs sample --persist` |

Region hardcoded to `de` — no `--region` flag (see gotcha below). Auth
falls back `ALGOLIA_INSIGHTS_API_KEY` -> `ALGOLIA_LOGS_API_KEY` ->
`ALGOLIA_API_KEY` (the **logs** ACL is what the live API accepts). `metrics`
sums `/1/metrics` buckets into `totals` (nulls contribute 0) plus a derived
`error_rate = sum(errorCount)/sum(eventCount)`, labeled
`derived/approximate`. `sample` aggregates the raw `/1/events` stream (never
dumps it raw — unreadable at ~3,000 rows) by `eventName`,
`eventType`/`eventSubtype`, `algoliaSource`, `client` (browser / Hotwire
Native Android / Hotwire Native iOS / server-side Ruby / other, from
`User-Agent`), ingest status, and error message; `queryID` presence is
broken down **per `eventType`** (a view event correctly never carries one).
`errors` groups failing events by `(error message, eventName,
algoliaSource, client)`. Both `sample` and `errors` report the observed
buffer window (`window.elapsed_minutes` = required sampling interval, same
convention as `logs sample`) and set `"truncated": true` with an explicit
warning whenever the fetch lands at/near the ~3,000-event cap.

### completions / manpage

```bash
alx completions bash
alx completions zsh
alx completions fish
alx completions powershell
alx manpage > alx.1     # hidden subcommand
```

Both intercepted in `main()` before `AppContext` is built — no HTTP client,
no credentials needed.

## Env Vars

| Var | Role |
|---|---|
| `ALGOLIA_APPLICATION_ID` | Required everywhere (or `--app-id`) |
| `ALGOLIA_LOGS_API_KEY` | Logs surface credential |
| `ALGOLIA_USAGE_API_KEY` | Usage surface credential |
| `ALGOLIA_ANALYTICS_API_KEY` | Analytics surface credential |
| `ALGOLIA_KEYS_API_KEY` | Keys-audit surface credential |
| `ALGOLIA_INSIGHTS_API_KEY` | Events (Insights API) surface credential |
| `ALGOLIA_API_KEY` | Generic fallback for every surface (checked after the per-surface var, before `--key`... — see precedence below) |
| `ALX_SERVER_SIDE_KEYS` | Comma-separated key prefixes for `keys audit`'s K2 hard-warning (same as repeatable `--server-side-key`) |

Precedence per command: `--key` (global flag) > per-surface env var >
`ALGOLIA_API_KEY`. **Never** reads `ALGOLIA_WRITE_API_KEY` or
`ALGOLIA_SEARCH_API_KEY` implicitly — those are the website's own
admin/public keys, not `alx`'s. `events` (Insights API) is the ONE surface
with an extra fallback tier: `--key` > `ALGOLIA_INSIGHTS_API_KEY` >
`ALGOLIA_LOGS_API_KEY` > `ALGOLIA_API_KEY` — the logs ACL is empirically
what the live Insights API accepts (measured 2026-08-04), so no new key
needs minting if a logs key is already configured.

Test-only hidden overrides (never set outside `cargo test` — do not
reference these when debugging a real run): `ALX_LOGS_BASE_URLS`,
`ALX_SEARCH_BASE_URL`, `ALX_USAGE_BASE_URL`, `ALX_ANALYTICS_BASE_URL`,
`ALX_INSIGHTS_BASE_URL`, `ALX_ASN_STATIC_MAP`. They redirect
`AppContext::base_urls`/ASN resolution at a wiremock server or a synthetic
map so every command builder's tests run fully offline.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | generic/unexpected |
| 2 | clap usage error (clap's own) |
| 3 | network/timeout |
| 4 | auth: invalid key / missing ACL |
| 5 | plan-gated capability (Usage/Analytics not in plan) |
| 6 | safety refusal (over-privileged key, no `--i-know`) |

`AppError::exit_code()` (`src/error.rs`) is the single place this mapping
lives; `main()` is the single `std::process::exit` call site.

## Gotchas

- **Per-server 1,000-entry ring buffers — but the three hosts can return
  nearly the SAME buffer.** In practice, fanning out to all three of
  `{app}-1|2|3.algolianet.com` can fetch 3,000 entries that dedupe to
  barely more than the 1,000 a single host returns — 3× the operations
  quota for well under 1% more coverage. The design assumption
  (independent per-server buffers worth polling separately) does **not**
  necessarily hold — keep the dedupe, but treat the fan-out as possibly
  near-redundant and prefer `ALX_LOGS_BASE_URLS` pinned to one host for
  routine sampling until a `--single-host` flag exists.
- **On a busy app the buffer turns over in minutes.** 1,000 entries can
  span only a couple of minutes of traffic, so a daily sample captures a
  tiny fraction of a percent of it and even an hourly one only a few
  percent. `logs sample`'s `window.elapsed_minutes` is the number that
  tells you your *required* sampling interval, not a stat to skim past.
- **The Usage and Analytics APIs demand OPPOSITE date formats.** Verified
  live 2026-07-30 against both. Usage (`usage.algolia.com/1/usage/*`)
  requires a **full ISO-8601 datetime** (`2026-07-23T00:00:00Z`); a
  date-only value fails with a misleading
  `422 {"message":"Unexpected parameters: \"startDate\", \"endDate\""}` —
  it reports a *format* error as if the parameter *names* were wrong, which
  is why this originally looked like a naming mismatch. Search Analytics
  (`analytics.{region}.algolia.com/2/*`) requires the exact opposite —
  **date-only** (`2026-07-28`); a datetime fails with
  `"startDate must be a date (e.g: 2006-01-14)"`. `usage::date_window` and
  `analytics::date_window` are deliberately separate helpers; do not
  "unify" them.
- **Every Search Analytics endpoint requires `index`, including
  `/2/status`.** Omitting it returns `422 "Index is required"`, which a
  capability probe would otherwise report as an opaque `unknown`. Verified
  live 2026-07-30.
- **The Usage API response is keyed by statistic name**, i.e.
  `{"total_search_requests": [{"t": <unix ms>, "v": <number>}]}` — not the
  `{"statistics": [...]}` envelope the pre-build research claimed. `t` is
  **milliseconds**, not seconds. `parse_usage_response` accepts both shapes;
  the statistic-name form is the real one.
- **Logs calls consume operations quota and are themselves invisible in the
  logs.** Every `logs`/`usage`/`analytics`/`keys` call `alx` makes counts
  against Algolia's operations quota, and a logs call never shows up as an
  entry in the logs it fetches. `session_ops` in every response envelope
  (and the closing human-mode line) exists solely so an operator can see
  this cost — never remove it from a new command's response struct.
- **Usage/analytics are plan-gated, not just ACL-gated.** A 402, or a 403
  whose body mentions plan/feature/"not available", classifies as
  `plan_gated` (`http::classify_forbidden`) — distinct from a missing-ACL
  401/403. Never let a plan-gated failure surface as a raw error dump;
  `doctor` and every usage/analytics command must classify it.
- **KEEP-list carve-outs (`src/constants.rs::KEEP_ASNS`).** `{62044, 53813,
  22616}` (Zscaler corporate proxy ranges), `13335` (Cloudflare/WARP),
  `16509` (Amazon AWS), `15169` (Google — but gated: Googlebot/
  Storebot UA routes to `Crawler`, not `Keep`). Plus
  `PRIVATE_RELAY_ASNS` (`20940`/`16625`/`35994` Akamai, `54113` Fastly)
  combined with an iOS UA → `PrivateRelayProbable`, never flagged as
  offsite abuse. Do not hand-edit these lists casually; a stale KEEP list
  produces false-positive "abuse" on real Zscaler/WARP/iCloud shoppers.
- **`--i-know` gate.** Before the first real call on `logs`/`keys audit`/
  `usage`/`analytics`, `alx` best-effort self-inspects the configured key
  (`GET /1/keys/{key}`) and refuses (exit 6) if its ACL set intersects
  `{addObject, deleteObject, deleteIndex, editSettings, settings}` — unless
  `--i-know` is passed. `doctor` deliberately does **not** run this gate
  (see above). Self-inspect failure (403/404/network) never blocks — it
  proceeds silently except in `--verbose`.
- **Canonical header casing.** Every request sets `X-Algolia-Application-Id`
  and `X-Algolia-API-Key` (mixed-case) — not `Authorization:`. Notes that
  suggest otherwise are wrong; the mixed-case pair is what
  `algosearch`'s working client and this codebase both use. Keep code and
  docs consistent (algosearch's own code/docs mismatch on this exact point
  was flagged and deliberately not repeated here).
- **Never format a raw `reqwest::Error` from a `/1/keys/{key}` self-read.**
  `reqwest::Error`'s `Display`/`Debug` unconditionally embeds the full
  request URL on a transport-layer failure, and that URL contains the key
  value as a path segment. `algolia::keys::redact_self_read_network_error`
  and `safety::preflight_privilege_check`'s network-error branch both
  intercept this before it can reach `AppError::Network` — any new call
  site building a URL containing a key value must do the same.
- **Granularity/window pre-flight, not server-side rejection.** `usage
  series --granularity hourly --since 30d` fails cleanly before any HTTP
  call (`hourly` supports ≤7d, `daily` ≤365d — the design spec's numbers,
  not an unverified `daily≤90d` claim seen during research).
- **`/1/events` is a rolling ~3,000-event buffer, NOT a time-windowed
  query.** Measured 2026-08-04: a 10-minute, 1-hour, 1-day, and 30-day
  window ALL returned ~2,990-2,997 events — the same most-recent buffer,
  regardless of the requested `startDate`/`endDate`. `offset`/`page`/
  `length` all return 0 events (verified live) — there is NO pagination
  workaround; `limit` only truncates. Same class of problem as the Logs
  API's 1,000-entries-per-server cap, and `events sample --persist` is
  modeled on `logs sample --persist` for exactly that reason.
- **Insights `insights.us.algolia.io` -> 401, not an empty-region 200.**
  Verified live 2026-08-04 — this is a DIFFERENT failure class than the
  Search Analytics API's `us` region (which 200s with `updatedAt: null` for
  no data). Never model the Insights `us` 401 as "no data for this region";
  it is an auth failure. This app's Insights traffic lives on `de`, hardcoded
  in `commands::events` — no `--region` flag exists for `events`.
- **Insights `/1/metrics` `granularity=week` -> HTTP 422**, verified live
  2026-08-04. `EventsGranularity` (the CLI enum) has only `Hour`/`Day`
  variants — `week` is structurally unrepresentable from the command line —
  and `algolia::insights::validate_metrics_granularity` re-checks the raw
  string defensively before every fetch regardless.
- **`alx keys audit`'s K2 check needs operator input.** Algolia's key
  metadata has no "also used server-side" field — the NAT hazard (a
  rate-limited key that is also called from servers egressing through a
  few NAT IPs) can only be flagged as a *hard* warning if you
  pass `--server-side-key`/`ALX_SERVER_SIDE_KEYS`; absent that, a
  rate-limited browser-restricted key only gets a lower-severity advisory.

## Project Structure

```
src/main.rs                # tokio::main; intercept Completions/Manpage before
                            #   AppContext; match-dispatch to commands::*::run;
                            #   single exit_code() -> process::exit mapping
src/cli.rs                  # Cli{global flags} + Commands enum + one XArgs
                            #   struct per subcommand + SinceArg (FromStr)
src/context.rs               # AppContext{client, presenter, ops, base_urls};
                            #   resolve_app_id()/resolve_key(surface) — the
                            #   D3 credential precedence, in one place
src/error.rs                 # AppError (thiserror) + exit_code() + suggestion()
src/http.rs                  # get_json(): the ONLY HTTP method exposed (GET);
                            #   429 backoff, classify_forbidden, SessionOps
src/output.rs                 # Presenter: JSON-default, --human/--jq, error()
                            #   stdout-in-JSON/stderr-in-human split
src/agent.rs                  # LLM-agent auto-detection (lifted from algosearch)
src/display.rs                # kv_line/heading/status_marker human helpers
src/constants.rs              # FRONTEND_INDEXES, KEEP_ASNS, PRIVATE_RELAY_ASNS,
                            #   ORIGIN_ALLOW_PATTERN, UA regex patterns
src/safety.rs                 # mask_key, preflight_privilege_check (--i-know gate)
src/asn.rs                    # Team Cymru origin-DNS ASN lookup + classify()
src/algolia/
  ├── logs.rs                 # fetch layer: 3-host fan-out, String coercion,
  │                           #   query_headers parsing, dedupe
  ├── keys.rs                 # list_keys/get_self/audit_fetch, KeyInfo (hand-
  │                           #   written Debug to keep `value` redacted)
  ├── usage.rs                 # fetch_statistic, granularity/window pre-flight,
  │                           #   sum_series/latest_value
  ├── analytics.rs              # top_searches/no_results/no_result_rate,
  │                             #   Throttle (A1), region-404 suggestion
  └── insights.rs                # fetch_metrics/fetch_events, MetricPoint/
                                #   RawEvent (all-Option null-tolerant),
                                #   validate_metrics_granularity
└── commands/
    ├── doctor.rs                # capability-matrix probes
    ├── logs.rs                   # sample/offsite/errors, --persist claiming
    ├── keys.rs                   # K1/K2 warning logic
    ├── usage.rs                  # U1/U3/U4/U5 response assembly
    ├── analytics.rs               # scrape-signal heuristics (A2/A3)
    └── events.rs                  # metrics totals, sample aggregation
                                  #   (event_name/type/source/client/status/
                                  #   error/queryID/userToken buckets),
                                  #   buffer-cap truncation warning,
                                  #   --persist claiming (adapted from logs.rs)
```

Shared plumbing (`cli.rs`, `error.rs`, `http.rs`, `output.rs`, `context.rs`,
`agent.rs`, `constants.rs`, `safety.rs`, `asn.rs`) is frozen scaffold —
changes there ripple across every command and should not be made lightly.
Each `commands/{doctor,logs,keys,usage,analytics,events}.rs` plus its
`algolia/*.rs` counterpart is independently owned. Full narrative reference:
`README.md`.
