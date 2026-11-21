# Accela Imageboard Engine

Anonymous-first imageboard engine on **Elixir 1.20** (native gradual type
checker), **Ash 3.37**, **AshPostgres**, **Phoenix 1.8 + LiveView 1.2**,
**PostgreSQL 19**.

## Architecture

Three Ash domains, split along the trust boundary (public anonymous vs
authenticated staff):

```
lib/accela_imageboard/
├── accounts.ex            # staff authentication (AshAuthentication, password)
│   └── accounts/           # User (is_staff flag), Token, Scope
├── boards.ex               # public content: board/thread/post/media
│   ├── boards/
│   │   ├── changes/        # SetPosterHash, RateLimit, BannedPoster,
│   │   │                   # CreateOpPost (OP inside thread-create txn), BumpThread
│   │   └── checks/         # BoardOpen, ThreadOpen, ReplyBumpFlow, OpPostFlow, PostFlowAttach
├── moderation.ex           # staff-only: Ban, Report (state machine), ActionLog
├── media/                  # magic-byte validation, traversal-proof storage
├── auth/pbkdf2_hash_provider.ex   # password hashing (pure-OTP PBKDF2)
├── security/ip_hash.ex            # anonymous identity: keyed HMAC of IP
└── rate_limits.ex          # hammer (ETS) rate limiting
```

### Security model

* **Anonymous identity** — visitors post without accounts; they are
  identified by `HMAC-SHA256(ip, secret)` (`IP_HASH_SECRET`). Raw IPs are
  never stored, and the hash is never accepted from user input (anti-spoofing,
  verified by tests).
* **Authorization** — resource-level Ash policies: public read/create on open
  content, staff-only management (`AccelaImageboard.PolicyChecks.Staff`).
  Parent-state rules use custom checks (`BoardOpen`, `ThreadOpen`) because
  `expr(parent.attr)` cannot be evaluated on create. Internal flows use
  server-side context markers (`ReplyBumpFlow`, `OpPostFlow`, `PostFlowAttach`)
  — client input can never forge them.
* **Bans** — enforced in the posting flow via `BannedPoster`; **fails closed**
  (a lookup error denies the post).
* **Rate limiting** — per-identity buckets via `hammer` (keyset: thread ≥5/10min,
  post ≥20/5min, report ≥10/15min, configurable via `:rate_limits`). One human
  action = exactly one token (an OP burns `thread_create`, never also
  `post_create`).
* **Transport headers** — `SecureHeaders` plug: CSP from config (strict prod
  default), HSTS, `X-Frame-Options: DENY`, `nosniff`, COOP/COEP,
  `Cross-Origin-Resource-Policy: same-origin` (anti-hotlinking),
  `Permissions-Policy`.
* **Password hashing** — PBKDF2-HMAC-SHA256 (600k iterations) from Erlang/OTP
  `:crypto`. Zero NIFs on Windows (bcrypt stubbed, see
  `vendor/bcrypt_elixir_stub/`).

### Anti-abuse & privacy notes

* Confirmation emails for staff accounts are printed to the console in dev
  (no mailer configured yet — roadmap item).
* `AshAdmin` console is dev-gated **and** behind Basic Auth
  (`:dev_admin_basic_auth`).
* Poster hashes are pseudonymous identifiers; rotating `IP_HASH_SECRET`
  invalidates them all — treat that key as production-critical.
* `post_bump` from replies is post-commit (`after_transaction`): a crash
  between reply and bump can leave ordering stale until the next reply
  (benign; documented in `Boards.Thread`).

## Roadmap

Status legend: ✅ done · 🔜 next · ⬜ planned. Quality bar for all phases:
docs-first (see AGENTS.md), TDD, `mix check` fully green.

### ✅ Phase 0–3 — Foundation (shipped, commit 854f27e)

Security-first domain split, hardening from a triple-agent audit (156 tests),
hot-path indexes EXPLAIN-verified, keyset pagination on all public reads,
Oban wired (`default` + `media` queues), idempotent seeds (admin via
`SEED_ADMIN_PASSWORD`), full web vertical: board index → thread list →
thread, anonymous posting with media upload (magic-byte validated,
traversal-proof storage, controller-served with nosniff/immutable cache),
OP-on-thread-create, reply bumps.

### 🔜 Phase 4 — Real-time threads (websockets)

Live updates over the existing LiveView websocket channel — **no polling**.

| Item | Design (Ash/Phoenix-native) |
|---|---|
| Live posts in an open thread | `Ash.Notifier.PubSub` on `Post` (`broadcast_type :phoenix_broadcast`), topics `thread:{id}`; `ThreadLive` subscribes on mount and appends via `Phoenix.LiveView.stream/3` |
| Live board ordering | Publish thread bump events to `board:{slug}`; `BoardLive` prepends/moves rows in a stream |
| Correctness under races | Treat notifications as *refresh hints*: reconcile via an authoritative `Ash.read` (keyset) — never trust broadcast payloads as data |
| Security | Topic scope = what the visitor may read (hidden board/private threads never broadcast); ban ⇒ `Endpoint.broadcast("users_sessions:...", "disconnect")`-style eviction; `connect-src 'self'` CSP already enforced |
| Multi-node | `Phoenix.PubSub` PG backend — no code change, deploy note |

Docs to consult: `deps/ash/documentation/dsls/DSL-Ash.Notifier.PubSub.md`,
`deps/phoenix_pubsub`, LiveView streams guide (hexdocs).

### ⬜ Phase 5 — Media processing

* Thumbnail generation (Oban `media` queue worker; ImageMagick via scoop,
  graceful skip if the binary is missing), serve sizes via the media
  controller with the same nosniff/cache discipline.
* sha256 dedup already exists on `Media`; add "already posted in this
  thread" UX.
* Optional EXIF stripping in the worker.

### ⬜ Phase 6 — Production readiness

* Swoosh mailer (+ prod adapter), real confirmation/reset emails.
* GitHub Actions CI: `mix check`, `mix hex.audit`, dialyzer on PRs.
* Telemetry: Ash metrics into LiveDashboard (`deps/ash/documentation/topics/monitoring.md`).
* Staff UI beyond AshAdmin: `/staff` routes behind `is_staff` with the
  moderation queue and report triage.

### ⬜ Phase 7 — Moderation UX

* Mod queue LiveViews (offset-paginated `:moderation_queue` exists), one-click
  moderate/ban with ActionLog already written domain-side, report state
  machine transitions with audit trail.

### ⬜ Phase 8 — Scale & resilience

* Oban cron: auto-archive stale threads, rate-limit bucket TTL hygiene.
* Load tests around the reply path (rate limiter + bump + broadcast);
* OpenTelemetry if multi-node deploy lands.

## Getting started

Requires: Elixir 1.20+, Erlang/OTP 27+, PostgreSQL (scoop: `scoop install
postgresql`, then `pg_ctl start` — see `.env.example.ps1` for default creds).

```powershell
mix setup        # deps + database (create/migrate incl. oban) + seeds + assets
mix phx.server   # http://localhost:4000
```

Database and secrets come from env vars with sane dev defaults — see
`.env.example.ps1`. Set `IP_HASH_SECRET` and `SEED_ADMIN_PASSWORD` in any real
environment. `mix ash.migrate` and rerun `mix run priv/repo/seeds.exs` after
pulling.

## Quality & security gates

The project uses Elixir 1.20's **native gradual type checker** (active on
every `mix compile`; only verified bugs are reported) plus:

```powershell
mix check        # format-check → compile --warnings-as-errors → credo
                # → sobelow (SAST) → doctor (docs) → tests
mix hex.audit    # advisories in the lockfile (run before releases)
```

Also available: `mix dialyzer`, `mix coveralls.html`, `mix test.watch`.
CI should run `mix check` and `mix hex.audit` on every push.

## Development workflow (TDD)

1. **Red** — write the domain spec first (`test/accela_imageboard/*`):
   actions, policies, and abuse controls are plain function calls, no HTTP
   needed. Keep rate-limit tests isolated with unique poster identities.
2. **Green** — implement the action/policy/change in the resource.
3. **Refactor** — `mix check` until fully green.

Migrations: change resources → `mix ash.codegen describe_the_change` →
review the generated migration → `mix ash.migrate`. Consulting
`AGENTS.md` is mandatory before touching domain security or realtime code.
