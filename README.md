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
│   │   ├── changes/        # SetPosterHash, RateLimit, BannedPoster
│   │   └── checks/         # BoardOpen, ThreadOpen (policy checks)
├── moderation.ex           # staff-only: Ban, Report (state machine), ActionLog
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
  `expr(parent.attr)` cannot be evaluated on create.
* **Bans** — enforced in the posting flow via `BannedPoster`; **fails closed**
  (a lookup error denies the post).
* **Rate limiting** — per-identity buckets via `hammer` (thread ≥5/10min,
  post ≥20/5min, report ≥10/15min; configurable via `:rate_limits`).
* **Transport headers** — `SecureHeaders` plug: CSP (no inline scripts in
  prod), HSTS, `X-Frame-Options: DENY`, `nosniff`, COOP/COEP, and
  `Cross-Origin-Resource-Policy: same-origin` (anti-hotlinking).
* **Password hashing** — PBKDF2-HMAC-SHA256 (600k iterations) from Erlang/OTP
  `:crypto`. bcrypt needs an MSVC toolchain on Windows; this uses zero NIFs.
  See `vendor/bcrypt_elixir_stub/` for how to restore real bcrypt if you get
  a C toolchain.

### Anti-abuse & privacy notes

* Confirmation emails for staff accounts are printed to the console in dev
  (no mailer configured yet — install one before production).
* `AshAdmin` console is mounted at `/admin` but **only in `:dev_routes`**;
  before exposing it in any other environment, gate it behind staff auth.
* Poster hashes are pseudonymous identifiers. Rotating `IP_HASH_SECRET`
  invalidates them all — treat that key as production-critical secret.

## Getting started

Requires: Elixir 1.20+, Erlang/OTP 27+, PostgreSQL (scoop: `scoop install
postgresql`, then `pg_ctl start` — see `.env.example.ps1` for default creds).

```powershell
mix setup        # deps + database (create/migrate) + assets
mix phx.server  # http://localhost:4000
```

Database and secrets come from env vars with sane dev defaults — see
`.env.example.ps1`. Set `IP_HASH_SECRET` in production.

## Quality & security gates

The project uses Elixir 1.20's **native gradual type checker** (active on
every `mix compile`; only verified bugs are reported) plus:

```powershell
mix check    # format-check → compile --warnings-as-errors → credo
             # → sobelow (SAST) → doctor (docs) → tests
mix hex.audit   # advisories in the lockfile (run before releases)
```

Also available: `mix dialyzer` (PLT build is slow the first time),
`mix coveralls.html` (coverage report in `cover/`), `mix test.watch`.

CI should run `mix check` and `mix hex.audit` on every push.

## Development workflow (TDD)

1. **Red** — write the domain spec first (`test/accela_imageboard/*`):
   actions, policies, and abuse controls are plain function calls, no HTTP
   needed. Keep rate-limit tests isolated with unique poster identities.
2. **Green** — implement the action/policy/change in the resource.
3. **Refactor** — `mix check` until fully green.

Migrations: change resources → `mix ash.codegen describe_the_change` →
review the generated migration → `mix ash.migrate`.
