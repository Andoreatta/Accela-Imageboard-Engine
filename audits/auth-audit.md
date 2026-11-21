# Security Audit — Accela Imageboard Engine

**Scope:** authentication, secrets, moderation
**Mode:** read-only static audit; no repository file was modified (this report is the only file written)
**Stack verified:** Elixir 1.20.5 / OTP 29, Phoenix 1.8, Ash 3.37, AshAuthentication 5.0-rc, AshPostgres
**Date:** audit performed against the working tree as it stood at time of review

## Summary

| # | Category | Verdict |
|---|----------|---------|
| 1 | Password hashing (PBKDF2) | **Core parameters sound.** 3 low findings (nil-input crash, no iteration floor, non-PHC base64). No attacker-controlled parameter path found. |
| 2 | bcrypt stub | **No reachable call path today.** 1 low finding (detection is impossible because the fake module loads). Silent failure mode is a *future* runtime 500, not a bypass. |
| 3 | Token / session secrets | **Fail-closed and mostly sane.** 3 low findings (empty-secret accepted, committed dev secrets, cookie without `secure`). |
| 4 | IP hash | **Weakest area.** 3 medium findings (IPv6 /64 evasion, unwired `IP_HASH_SECRET`, blind XFF trust). Constant-time compare and full-length digest are fine. |
| 5 | Moderation | **State machine and ban expiry logic correct.** 2 medium findings (audit-attribution forgery, nothing writes the audit log) + minor gaps. |
| 6 | `PolicyChecks.Staff` | **1 medium finding** — bare-map actor satisfies the check. No reachable attack today, but the check is type-unsafe. |
| 7 | Seeds / migrations | **Clean — nothing found.** No default staff, no weak credentials anywhere. |

**Totals:** 19 findings — 0 critical, 0 high, 8 medium (F-08, F-09, F-10, F-12, F-13, F-16, F-18, F-19), 11 low.

---

## 1. Password hashing (`lib/accela_imageboard/auth/pbkdf2_hash_provider.ex`)

**What is right** (verified, not assumed): 600 000 iterations with PBKDF2-HMAC-SHA256 is exactly the OWASP 2023 recommendation; 16-byte per-hash CSPRNG salt; 32-byte derived key; verification uses `Plug.Crypto.secure_compare/2` (`pbkdf2_hash_provider.ex:44`); `simulate/0` burns one full real hash so the unknown-user path in `SignInPreparation` costs the same as a real check (`pbkdf2_hash_provider.ex:54`).

**Attacker-controlled iterations: not reachable.** `valid?/2` does re-read `iterations` from the stored string (`pbkdf2_hash_provider.ex:43`), which is the classic "verify with parameters from the hash" smell — but `hashed_password` appears in **no** `accept`/argument list on any action (`user.ex:88,103`, and the auth actions only take `password`/`password_confirmation`, hashed server-side by `HashPasswordChange`). Writing an arbitrary hash requires DB access, at which point the attacker owns the account anyway. **Not a finding.**

### F-01 · low · `valid?/2` has no `nil` clause

`lib/accela_imageboard/auth/pbkdf2_hash_provider.ex:40`

`def valid?(input, stored) when is_binary(input) and is_binary(stored)` — both reference implementations (`BcryptProvider`, `Argon2Provider`) define `valid?(nil, _hash)` → `no_user_verify()` → `false`. Here a `nil` on either side raises `FunctionClauseError` inside the Ash action.

*Why it matters:* it converts "no password set / field not selected" from a clean authentication failure into a 500 in `change_password` (`PasswordValidation` reads `Changeset.get_data/2`) and in custom sign-in flows. Fails closed, but as a crash — noisy, and a distinguishable response oracle.

*Fix:* add `def valid?(nil, _stored), do: simulate()` and `def valid?(_input, nil), do: simulate()`.

### F-02 · low · no iteration floor; PHC string is not PHC

`lib/accela_imageboard/auth/pbkdf2_hash_provider.ex:77` and `:69`

`iterations > 0 and iterations <= 10_000_000` accepts a 1-iteration hash, so a downgraded/imported row verifies silently and forever. And `Base.encode64/1` emits *padded* base64, whereas PHC/crypt uses unpadded base64 — so a hash produced here cannot be verified by passlib/Django/`:pbkdf2_elixir`, and a hash imported from them cannot be verified here.

*Why it matters:* the module claims "PHC-style" and names Django/passlib as the reference; the format will silently diverge on any future migration or shared-auth deployment (every staff login stops working, with no error explaining why).

*Fix:* floor at the current `@iterations` (accept only `iterations >= 600_000`, or rehash-on-login for lower values); encode with `Base.encode64(salt, padding: false)` and document the format as *not* PHC.

### F-03 · low · blanket `rescue` in `hash/1`

`lib/accela_imageboard/auth/pbkdf2_hash_provider.ex:31`

`rescue _ -> :error` swallows every exception, including bugs and genuine `:crypto` failures, and `hash/2` inherits it. Registration/password-change then fails with a generic "could not hash" and nothing in the log.

*Fix:* drop the rescue (or `:error` with a `Logger.error/1`).

---

## 2. The bcrypt stub (`vendor/bcrypt_elixir_stub/`)

**Can reachable code call it?** I traced every consumer in `deps/ash_authentication`: `Bcrypt` is referenced **only** from `AshAuthentication.BcryptProvider`. The app's only password strategy sets `hash_provider AccelaImageboard.Auth.Pbkdf2HashProvider` (`user.ex:42`), `remember_me` in AS 5.0 has **no** hash provider (verified in `strategies/remember_me/*`), recovery codes are not enabled, and no app code mentions `Bcrypt`. **No reachable call path exists today.** If one appeared, it raises — fail-closed, never silent-accept.

### F-04 · low · the stub makes misuse undetectable at compile time

`vendor/bcrypt_elixir_stub/mix.exs`, `vendor/bcrypt_elixir_stub/lib/bcrypt.ex`

AshAuthentication's own guard is `validate_hash_provider_dep/1` → `Code.ensure_loaded?(Bcrypt)` (`deps/ash_authentication/lib/ash_authentication/strategies/password/verifier.ex:79`). Because the stub defines a module named `Bcrypt`, that check **passes**. So if anyone copies a snippet from the Ash docs (`hash_provider AshAuthentication.BcryptProvider`) or removes the `hash_provider` line (default is BcryptProvider), compilation succeeds, `mix check` succeeds, and the failure appears only when a real user submits the sign-in form — a 500 on every sign-in/registration, i.e. total staff lockout discovered in production.

Second hazard: the stub claims `app: :bcrypt_elixir` at version 3.3.2 with `override: true`. If the hex dependency is ever restored while the path dep lingers, two `Bcrypt` modules with the same name are defined and one silently wins (an "already defined" warning at best, undefined behaviour at worst).

*Fix:* make the assumption testable — add a test asserting every password strategy's `hash_provider` is `AccelaImageboard.Auth.Pbkdf2HashProvider` (e.g. `AshAuthentication.Info.strategies/2`), and keep the restore instructions next to the dep in `mix.exs`.

---

## 3. Token / session secrets

`Secrets.secret_for/4` (`lib/accela_imageboard/secrets.ex:12`) returns `Application.fetch_env/2` — runtime, never compile-time. Prod **raises at boot** if `TOKEN_SIGNING_SECRET` or `SECRET_KEY_BASE` is missing (`config/runtime.exs:66,89`). `store_all_tokens? true` + `require_token_presence_for_authentication? true` (`user.ex:35`) mean JWTs are DB-checked per request, which additionally neutralises forged-or-replayed JWTs with unknown `jti`. This is the correct shape.

### F-05 · low · empty `TOKEN_SIGNING_SECRET` is accepted

`config/runtime.exs:89-91`

`System.get_env("TOKEN_SIGNING_SECRET") || raise` — `""` is truthy in Elixir, so `TOKEN_SIGNING_SECRET=""` (or a 3-character value, e.g. from a templating mistake) passes and HMAC-signs tokens with a guessable key. Phoenix validates `secret_key_base` length itself; nothing validates this one. Impact is blunted by the DB token check (a forged JWT's `jti` won't exist), but the same secret also signs `sign_in_with_token` exchange tokens.

*Fix:* `secret = System.fetch_env!("TOKEN_SIGNING_SECRET")` plus `if byte_size(secret) < 32, do: raise "TOKEN_SIGNING_SECRET too short"`.

### F-06 · low · committed secrets in dev/test

`config/dev.exs:26` (`secret_key_base`), `config/dev.exs:58` (`token_signing_secret`), `config/test.exs:2,23`, `config/config.exs:34` (`live_view signing_salt: "gD5oVa07"`)

These are the `phx.new`-generated values. Prod is structurally protected (runtime.exs raises; `dev_routes` is undefined in prod). The real coupling problem is that the **dev `secret_key_base` is also the IP-hash pepper** — see F-08.

### F-07 · low · session cookie has no `secure: true`

`lib/accela_imageboard_web/endpoint.ex:7-12`

`@session_options` sets `store`, `key`, `signing_salt`, `same_site: "Lax"` — no `secure: true`, and no `encryption_salt` (the cookie is readable, as documented). Mitigated by prod `force_ssl` (`config/prod.exs:11`) which rewrites on `x-forwarded-proto`, so an attacker who can strip that header or reach the origin over plaintext gets the staff session cookie.

*Fix:* add `secure: Application.compile_env(:accela_imageboard, :secure_cookies, false)` and set it `true` in prod.

---

## 4. IP hash (`lib/accela_imageboard/security/ip_hash.ex`)

**Correct:** HMAC-SHA256, full 64-hex digest (no truncation), `Plug.Crypto.secure_compare/2` in `verify?/2` (`ip_hash.ex:39`), canonicalization through `:inet.parse_address` → `:inet.ntoa` so compressed/decompressed IPv6 forms collapse to one identity.

### F-08 · medium · `IP_HASH_SECRET` is documented but never wired; pepper silently falls back to `secret_key_base`

`lib/accela_imageboard/security/ip_hash.ex:56-66`, `config/runtime.exs` (no `IpHash` config), `.env.example.ps1:13`

The moduledoc, the `raise` message and `.env.example.ps1` all state that production **MUST** set `IP_HASH_SECRET` via `config :accela_imageboard, AccelaImageboard.Security.IpHash, secret: System.fetch_env!("IP_HASH_SECRET")` — that line **does not exist** in `config/runtime.exs`. So the env var an operator dutifully sets is read by nobody, and the pepper is `secret_key_base`.

*Why it matters:*

- Purpose separation is lost: rotating the cookie secret (a normal, expected operation) silently invalidates **every** poster hash — all bans stop matching and every rate-limit bucket resets, with no error anywhere.
- The fallback chain means an instance running the committed dev/test `secret_key_base` has a *public* pepper. With a known pepper the "identity cannot be recovered" claim collapses: an IPv4 space is 2^32, and a 2^32-strong HMAC-SHA256 sweep is minutes on one GPU. Any leak of poster hashes (report/ban rows, an admin dump, a DB backup) becomes a full IP deanonymization.
- There is no minimum-length check on the secret either.

*Fix:* add to `config/runtime.exs` under `config_env() == :prod`:

```elixir
config :accela_imageboard, AccelaImageboard.Security.IpHash,
  secret: System.fetch_env!("IP_HASH_SECRET")
```

and drop the `secret_key_base` fallback in `pepper/0` (or at least log a one-time warning).

### F-09 · medium · no IPv6 prefix normalization → ban and rate-limit evasion

`lib/accela_imageboard/security/ip_hash.ex:46-53`

The hash is of the **whole address**. Any client with an IPv6 allocation (a residential /64, a mobile /56, a VPS /48) can rotate source addresses at will, producing a fresh `poster_hash` per request. That defeats every control keyed on it: `BannedPoster` (`lib/accela_imageboard/boards/changes/banned_poster.ex:47`) and all three Hammer buckets (`lib/accela_imageboard/rate_limits.ex`).

Related, same function: an IPv4-mapped address (`::ffff:1.2.3.4`, which Bandit returns for IPv4 clients on a dual-stack socket) normalizes to the *string* `"::ffff:1.2.3.4"` and hashes differently from `"1.2.3.4"`. One poster, two identities, two buckets — a free ban bypass just by switching between `-4` and `-6`.

*Fix:* normalize to a network prefix before hashing — `/64` for IPv6, `/32` for IPv4 — and canonicalize IPv4-mapped IPv6 down to plain IPv4 (`:inet.ntoa` on the unmapped tuple). One function, ~10 lines, closes both.

### F-10 · medium · `X-Forwarded-For` trusted blindly when `trusted_proxies` is non-empty

`lib/accela_imageboard_web/plugs/request_context.ex:29-42`

`trusted = Application.get_env(…, :trusted_proxies, [])` then `if trusted != []` — the configured *addresses are never used*. The setting is a boolean in disguise: either "trust nobody" or "trust any XFF header from anyone". When enabled, `X-Forwarded-For: 1.2.3.4` from the client sets the poster identity outright → ban evasion, rate-limit evasion, and framing another IP.

Corollary in the other direction: with `trusted_proxies` left at `[]` behind a real load balancer, **every** poster shares the proxy's hash — one ban silences the whole site and one rate-limit bucket throttles everybody after 20 posts.

*Fix:* use the configured list against `conn.remote_ip` (or use `Plug.RemoteIp` / `RemoteIp` plug) and take the rightmost untrusted hop, not `List.first(String.split(","))` (leftmost is the client-supplied, spoofable end).

### F-11 · low · `verify?/2` and `hash/1` raise on bad input

`lib/accela_imageboard/security/ip_hash.ex:32,52`

`verify?/2` is dead code today (nothing calls it), but its contract is `boolean()` while it raises on any non-IP `ip` and never validates `stored_hash` shape. If it is later used as `if IpHash.verify?(...)` inside a `before_action`, malformed input becomes a crash rather than a denial. Also `RequestContext` calls `IpHash.hash/1` on every request, so an adapter that reports `{:local, path}` (Unix socket) makes **every** request 500.

*Fix:* return `false` on parse failure; guard `hash/1` against `{:local, _}`.

### Not a finding

`hash/1`'s use of `Application.get_env(...)[:secret]` on a `nil` config is safe (`Access.get(nil, …) → nil`), so a fresh instance without any `IpHash` config falls through to the endpoint rather than crashing.

---

## 5. Moderation

**Correct:** ban expiry is evaluated as `is_nil(expires_at) or expires_at > ^now` with `now` computed once per call (`lib/accela_imageboard/moderation/ban.ex:56,64`) — no off-by-one, no permanently-truthy filter. `banned?/1` **fails closed** on any read error (`lib/accela_imageboard/boards/changes/banned_poster.ex:49-52`). Report transitions are behind `AccelaImageboard.PolicyChecks.Staff` (`lib/accela_imageboard/moderation/report.ex:25`) and AshStateMachine only permits `accept/reject/resolve` from valid states — **anonymous visitors cannot advance report state**; their only permitted action is `create`.

### F-12 · medium · audit attributions come from user input

`lib/accela_imageboard/moderation/action_log.ex:60`, `lib/accela_imageboard/moderation/ban.ex:69`

`create :log` accepts `:staff_id`; `create :ban` accepts `:issued_by_id`. Any staff member can therefore write an ActionLog row naming a *different* colleague, or issue a ban in someone else's name. The policy only checks "the actor is staff", never "the row names the actor".

*Why it matters:* for an audit trail this is the whole point of the table — `detail`/`action`/`target_*` are also free-form strings, so a staff member can fabricate a plausible record. Non-repudiation is lost; a disputed ban cannot be attributed.

*Fix:* remove both from `accept` and set them server-side:

```elixir
change(set_attribute(:staff_id, actor(:id)))
change(set_attribute(:issued_by_id, actor(:id)))
```

### F-13 · medium · the audit log is never written

`lib/accela_imageboard/moderation/action_log.ex`

A grep of `lib/` and `test/` finds **no** caller of `ActionLog` other than the resource itself; `Ban` and `Report` transitions also have no `Ash.Notifier`/`after_action` hook that logs. The "staff moderation actions (who did what, to what)" trail is currently aspirational: bans and report triage leave no actor-facing record at all.

*Fix:* add a notifier (or `ash_paper_trail` version action + `after_action`) on `Ban` / `Report` / post moderation that calls `ActionLog.log` with the actor.

### F-14 · low · append-only is a resource-level property only

`lib/accela_imageboard/moderation/action_log.ex:7,20,58`

Confirmed: `defaults([])` and no `update`/`destroy` action exists, so Ash cannot mutate a row. There is no DB-level protection (no trigger, no `REVOKE UPDATE, DELETE` grant), and `AshAdmin` mounts the domain with a policy toggle (see F-16). Acceptable for most deployments; state it explicitly rather than implying immutability.

*Fix (optional):* a Postgres trigger raising on `UPDATE`/`DELETE` for `moderation_action_logs`.

### F-15 · low · `Ban.read :check` is `get? true` over a non-unique attribute

`lib/accela_imageboard/moderation/ban.ex:59-65`

Nothing prevents two active bans for one `poster_hash` (no unique index), and `get?` errors on multiple results. Unused today (`BannedPoster` uses its own `Ash.read` and fails closed), but it is a fail-open trap for the first caller that writes `case Ban.check(hash) do {:ok, _} -> ...`.

*Fix:* make it a `read` returning a list, or add `prepare(build(limit: 1))`.

### F-16 · medium · unauthenticated `AshAdmin` with a one-click "auth bypassed" toggle

`lib/accela_imageboard_web/router.ex:97-105`, `config/dev.exs:57`

`scope "/admin" do pipe_through :browser; ash_admin "/" end` has **no authentication plug at all**, and `Accounts` opts in with `admin do show? true end` (`lib/accela_imageboard/accounts.ex:8`). AshAdmin ships a sidebar control (`toggle_authorizing`, `deps/ash_admin/lib/ash_admin/components/page_live.ex:421`) that flips every subsequent call to `authorize?: false` — from that click on, `users.is_staff`, `bans`, `reports` and `moderation_action_logs` are fully editable by an anonymous visitor, bypassing `PolicyChecks.Staff` entirely. Gated only by `dev_routes: true`, which is set in `dev.exs` and (correctly) absent from `prod.exs`/`runtime.exs`; `MIX_ENV=dev` runs are loopback-bound by default (`config/dev.exs:21`).

*Why it matters:* dev-only + loopback makes this medium, not critical — but it is one `MIX_ENV` mistake or one `ip: {0,0,0,0}` debug change away from total compromise of staff accounts and the moderation history. LiveDashboard at `/dev/dashboard` is likewise unauthenticated.

*Fix:* wrap both scopes in a `Plug.BasicAuth` (the commented advice in the same file says exactly this), or replace `ash_admin` with a staff-policy-guarded LiveView before any non-loopback dev/deploy.

### F-17 · low · reports accept an arbitrary `post_id`

`lib/accela_imageboard/moderation/report.ex:44,59`, `priv/repo/migrations/20261120234736_initialize.exs` (`reports.post_id :uuid`, no FK)

Anonymous create is intentional (`policy action_type(:create) → authorize_if(always())`), rate-limited to 10/15 min per hash, and `reporter_hash` cannot be spoofed (`SetPosterHash` reads only server-side context). But `post_id` is a bare uuid with no relationship or FK, so reports can be filed against posts that do not exist, cluttering the triage queue.

*Fix:* add the `belongs_to :post` relationship + FK (the migration generator will add the constraint).

---

## 6. `PolicyChecks.Staff`

### F-18 · medium · a bare map satisfies the staff check

`lib/accela_imageboard/policy_checks/staff.ex:15`

```elixir
def match?(%{is_staff: true}, _context, _options), do: true
```

`Staff` (and the parallel `actor_attribute_equals(:is_staff, true)` on `set_staff_flag`, `lib/accela_imageboard/accounts/user.ex:63`) authorize **any actor that is a map with `is_staff: true`** — `%{is_staff: true}`, `%{"is_staff" => true}`-decoded claims mapped to atoms, an Ecto-projected map, a stale cache entry. Nothing re-checks that the actor is an `AccelaImageboard.Accounts.User` record loaded from the DB.

*Why it matters:* today the actor always arrives as a `User` struct loaded per request by `load_from_session` → `get_by_subject`, which is genuinely good (demotion takes effect immediately because `is_staff` is re-read from the DB, and `store_all_tokens?`/`require_token_presence_for_authentication?` make revocation real). But the safe behaviour rests entirely on that invariant, and every staff-only control in the app — bans, action log, report triage, post/thread moderation, staff flag changes — funnels through these two checks. One future API plug that does `actor: claims_map` (the most natural way to authenticate a JSON client in Phoenix) turns into universal staff impersonation.

*Fix:* pattern-match the record type:

```elixir
def match?(%AccelaImageboard.Accounts.User{is_staff: true}, _context, _options), do: true
def match?(_actor, _context, _options), do: false
```

One word, and a crafted map can no longer pass.

---

## 7. Seeds / migrations / default credentials

**Nothing found.** `priv/repo/seeds.exs` is the untouched `phx.new` template (comments only) — no staff user, no password, no `is_staff: true` row, no hardcoded credential anywhere in `priv/repo/migrations/` (`users.is_staff` defaults to `false` at the DB level, `priv/repo/migrations/20261120234736_initialize.exs`). `mix setup` / `ecto.setup` run that empty file. The only staff-creating code is the test helper (`test/accela_imageboard/boards_test.exs:31-54`), which uses `authorize?: false` and never runs outside `MIX_ENV=test`.

Two adjacent notes:

- **Open registration.** `register_with_password` is reachable anonymously — `ash_authentication_phoenix`'s register form sets `%{private: %{ash_authentication?: true}}` (`deps/ash_authentication_phoenix/.../register_form.ex:96`), which matches the `AshAuthenticationInteraction` bypass (`lib/accela_imageboard/accounts/user.ex:57`). New accounts get `is_staff: false` and `is_staff` is not in any argument/accept list, so this is not privilege escalation — but it means "staff-only deployment" is not enforced by registration policy: anyone can create an account and reach the authenticated UI. Gate it if the site is staff-only.
- **Hardening gaps in the password policy:** `min_length: 8` and nothing else (`lib/accela_imageboard/accounts/user.ex:120`) — no breached-password check, and `brute_force_strategy` is left at its `nil` default (`deps/ash_authentication/lib/ash_authentication/strategies/password/dsl.ex:146`).

---

## F-19 · medium · unauthenticated 100 ms-CPU PBKDF2 amplification

`lib/accela_imageboard/auth/pbkdf2_hash_provider.ex:18,28`, `lib/accela_imageboard_web/router.ex:48-61`

Hammer is wired **only** into the Ash `RateLimit` change for post/thread/report creation; the `auth_routes` sign-in/registration endpoints have no rate limit and the password strategy configures no `brute_force_strategy`/audit log. I measured `:crypto.pbkdf2_hmac(:sha256, pw, salt, 600_000, 32)` on this machine (OTP 29): **~98–100 ms per call**, and confirmed it runs on a dirty CPU scheduler (a ticker process kept running under `+S 1:1`), i.e. it consumes a full core per in-flight request without blocking a normal scheduler. `simulate/0` burns the same 100 ms even for an unknown e-mail, so the cheap path costs exactly as much as the expensive one.

*Why it matters:* ~10 concurrent POSTs to `/auth/password/sign_in_with_password` saturate 10 cores; sustaining that from one client makes the site unresponsive, and it costs the attacker a few Mbps. The defensive choices (600 k iterations, timing-equal simulation) are what create the lever.

*Fix:* rate-limit the auth endpoints (a Hammer plug on the `:browser` pipeline scoped to `/auth/*` and `/sign-in`, keyed by IP hash + e-mail), configure `brute_force_strategy` on the password strategy, and consider capping concurrent hash work (a `Task.Supervisor` with `max_children`, or a semaphore around `hash/1`).

---

## Overall verdict

This is a **carefully built authentication layer with a genuinely sound cryptographic core and a thin, honest gap between its documentation and its wiring.** The PBKDF2 provider is OWASP-appropriate in every parameter that matters (600 k iterations, 16-byte salt, 32-byte key, constant-time comparison, timing-equal `simulate/0`), and the "verify with iterations from the stored hash" pattern — the usual weak spot in hand-rolled providers — is unreachable because `hashed_password` is server-computed and accepted by no action. The bcrypt stub, which looked like the most dangerous item on the list, has no reachable call path today and fails closed by raising; its real cost is diagnosability, not bypass. Moderation logic is correct where it is easy to be wrong: ban expiry is a clean predicate evaluated per call, ban checks fail closed on read errors, and report state transitions require a staff actor. The weaknesses cluster where the code trusts a value it does not re-derive: the staff check accepts any map with `is_staff: true` (F-18), the audit trail accepts `staff_id`/`issued_by_id` from input and is never actually written (F-12, F-13), the anonymous identity is a whole-IP hash with no IPv6 prefix normalization so a /64 defeats both bans and rate limits (F-09), and the `IP_HASH_SECRET` that three separate documents call **required** is read by no code, leaving `secret_key_base` — a value committed to this repository — as the effective pepper (F-08). None of those is remotely exploitable to take over an account today, but all four undermine a control the design claims to provide, and the two that need the least work — one pattern match in `Staff.match?/3`, one config line in `runtime.exs` — are exactly the ones worth fixing before any moderation UI is exposed.
