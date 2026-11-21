# Web-layer security audit — Accela Imageboard Engine

Read-only review of `router.ex`, `endpoint.ex`, the two plugs, all controllers, auth overrides/LiveUserAuth, `config/{runtime,prod,config,dev,test}.exs`, plus the dependency code paths they invoke (`plug 1.20.4`, `ash_authentication 5.0-rc`, `ash_authentication_phoenix 3.0-rc`) to confirm behaviour. No source files were modified; this report is the only file written.

| # | Sev | Finding | Location |
|---|-----|---------|----------|
| 1 | **High** | Open self-registration of "staff" accounts (`/register` + `POST /auth/user/register`) | router.ex:54, user.ex:40, user.ex:201 |
| 2 | **High** | `trusted_proxies` is read as a boolean, never as an allow-list → XFF spoofing once configured | request_context.ex:29-36 |
| 3 | **Medium** | Reset/confirm tokens printed to stdout (logs) instead of emailed | send_password_reset_email.ex:11, send_new_user_confirmation_email.ex:30 |
| 4 | **Medium** | Inline `<script>` in the root layout is blocked by the prod CSP (`script-src 'self'`) | root.html.heex:17-41, secure_headers.ex:79 |
| 5 | **Medium** | CSP variant chosen with `Mix.env()` inside a plug (not available in releases; build-env decides prod headers) | secure_headers.ex:32-34 |
| 6 | **Medium** | Session cookie has no `secure: true`; `force_ssl` exempts `Host: localhost` | endpoint.ex:7-12, prod.exs:15-21 |
| 7 | **Medium** | Email enumeration through `/register` (unique-identity error) | user.ex:288, router.ex:54 |
| 8 | **Low** | `connect-src 'self' wss:` allows any WebSocket destination | secure_headers.ex:83 |
| 9 | **Low** | HSTS only when `conn.scheme == :https`; no `preload`; not on redirect responses | secure_headers.ex:54-58 |
| 10 | **Low** | No `Permissions-Policy` header | secure_headers.ex:36-44 |
| 11 | **Low** | Malformed `X-Forwarded-For` → 500; no IPv4-mapped/port normalisation | request_context.ex:36, ip_hash.ex:44-50 |
| 12 | **Low** | Poster hash put in `conn.assigns` (needlessly template-visible) | request_context.ex:25 |
| 13 | **Low** | Dead `return_to` redirect pattern — becomes an open redirect if ever populated from params | auth_controller.ex:12, 28, 72, 77 |
| 14 | **Low** | Static/`NoRoute` responses bypass the whole header plug | endpoint.ex:22-27, router.ex:29 |
| 15 | Info | Global 8 MB multipart parsing on every route | endpoint.ex:46-51 |

---

## 1. Header plug (`plugs/secure_headers.ex`)

**F5 — Medium — the CSP variant is decided at *runtime* from a *build-time* value.**
`secure_headers.ex:32-34`: `default_csp(Mix.env())`.
*Why it matters:* two problems in one line. (a) `Mix` is not bundled in a `mix release`, so with no `content_security_policy` configured (none is — grep over `config/` returns nothing) the `||` does not short-circuit and every browser request raises `UndefinedFunctionError`, i.e. a 500 instead of a page. (b) Because the choice happens at runtime from `Mix.env()`, an image built with `MIX_ENV=dev|preview` ships the **relaxed** CSP (`script-src 'self' 'unsafe-inline'`, `ws://localhost:*`) to production.
*Fix:* pass the env from config, not from Mix: `Keyword.get(config, :csp_env, Application.get_env(:accela_imageboard, :env_tag, :strict))`, or simply always use the strict CSP and add the dev-only relaxation through `config/dev.exs` `content_security_policy:`. A one-line config override in dev removes `Mix.env()` from the plug entirely.

**F4 — Medium — the layout contains an inline script that the prod CSP blocks.**
`root.html.heex:17-41` has a raw `<script>` theme switcher; prod sends `script-src 'self'` (`secure_headers.ex:79`).
*Why it matters:* the theme bootstrap silently dies in prod (flash-of-wrong-theme), and the obvious "fix" people reach for is `'unsafe-inline'` in prod, which throws away the best XSS mitigation the app has. It also violates the project rule against inline `<script>` tags.
*Fix:* move the snippet into `assets/js/app.js` (or a colocated hook with `phx-update="ignore"`); keep `script-src 'self'` as-is.

**F8 — Low — `connect-src 'self' wss:`** (`secure_headers.ex:83`). `wss:` (bare scheme) matches *any* WebSocket host, so any future injection can exfiltrate over a socket. LiveView's socket is same-origin and is already covered by `'self'`. *Fix:* `connect-src 'self';` (or `'self' wss://<PHX_HOST>` interpolated from config).

**Other header decisions — sound, with notes.** `frame-ancestors 'none'` + `x-frame-options: DENY` (SecureHeaders runs after `:put_secure_browser_headers`, and `put_resp_header` replaces, so Phoenix's `SAMEORIGIN` is correctly overridden) · `object-src 'none'`, `base-uri 'self'`, `form-action 'self'` present · `nosniff`, COOP `same-origin`, COEP `require-corp`, CORP `same-origin` are consistent with same-origin-only assets · `style-src 'unsafe-inline'` is the accepted trade-off here: LiveView writes `style` attributes, and `style-src-attr` cannot be nonce'd, so this is the right call — keep it and do not extend `'unsafe-inline'` to `script-src`.

**Header injection: none.** Config-driven values are only ever used as header *values* via `Plug.Conn.put_resp_header/3`, and Plug 1.20.4 rejects `\r`, `\n`, `\x00` in values and `:` in keys (`Plug.Conn.InvalidHeaderError`, `deps/plug/lib/plug/conn.ex:2002`). A `content_security_policy` string containing CRLF fails closed.

**HSTS — F9, Low.** `secure_headers.ex:54-58` emits HSTS only when `conn.scheme == :https`. The proxy case is actually handled: `prod.exs` sets `rewrite_on: [:x_forwarded_proto]`, and `Plug.SSL.call/2` runs `Plug.RewriteOn` *before* the https check (`deps/plug/lib/plug/ssl.ex:407-408`), so `conn.scheme` is `:https` by the time the router runs — **provided the proxy sets `X-Forwarded-Proto`**. Residual gaps: (a) with `Host: localhost` / `127.0.0.1` the whole `Plug.SSL` plug is skipped (`exclude`), so such a request is served over plain http *and* never gets HSTS; (b) HSTS is absent from the 301 responses themselves (`hsts: true` is not set in `force_ssl`), so the first plain-http hit learns nothing; (c) no `preload`, and `includeSubDomains` is asserted without any evidence that every subdomain is https-only. *Fix:* set `force_ssl: [hsts: true, ...]` and drop the `hosts: ["localhost","127.0.0.1"]` exclusion in prod (use a health-check `paths:` exclusion instead); add `preload` only after auditing subdomains.

**Missing header — F10, Low.** No `Permissions-Policy`. *Fix:* add `{"permissions-policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()"}`. Absence of `X-XSS-Protection` is fine (modern guidance is to omit it or send `0`; nothing to do).

**F14 — Low.** The plug only runs in the `:browser` pipeline, so `Plug.Static` responses and unmatched-route 404s (`NoRouteError` is raised before any pipeline) carry no CSP/HSTS/frame headers. Low impact given `static_paths/0` is `assets fonts images favicon.ico robots.txt` (no uploads dir) and media is controller-served. *Fix (optional):* move the plug into `endpoint.ex` before `Plug.Static`.

---

## 2. RequestContext (`plugs/request_context.ex`)

**F2 — High — the "trusted proxies" gate is a boolean, not an allow-list.**
`request_context.ex:29-36`: `trusted = Application.get_env(..., :trusted_proxies, [])` then `if trusted != [] do` — the configured value is **never compared to `conn.remote_ip`**. The moduledoc ("only trust a forwarded IP when `TRUSTED_PROXIES` is configured") describes something the code does not do.
*Why it matters:* the moment an operator follows the docstring and sets `trusted_proxies: ["10.0.0.0/8"]` (which they must, to run behind a load balancer), **any** client can send `X-Forwarded-For: 1.2.3.4` and choose its own poster identity. The hash is the app's whole abuse-control substrate — rate limits (`Changes.RateLimit`), bans (`Moderation.Ban`) and post attribution (`SetPosterHash`) all key on it — so this is rate-limit and ban evasion, plus the ability to *frame* another poster's hash. This is the most security-relevant code path in the web layer because the config value invites exactly this mistake.
*Fix:* make it a real CIDR allow-list — parse `conn.remote_ip`, only consult XFF when the *peer* is in `trusted_proxies`, then walk the header from the right, skipping trusted hops, and take the first untrusted address:

```elixir
defp client_ip(conn) do
  trusted = Application.get_env(:accela_imageboard, :trusted_proxies, [])

  if trusted == [] or not trusted_peer?(conn.remote_ip, trusted) do
    conn.remote_ip
  else
    conn
    |> Plug.Conn.get_req_header("x-forwarded-for")
    |> Enum.join(",")
    |> rightmost_untrusted(trusted)
    |> Kernel.||(conn.remote_ip)
  end
end
```

Also note the second-order bug it hides: **today** `trusted_proxies` is unset, so behind the same proxy every visitor resolves to the *proxy's* IP — one shared poster hash, i.e. one global rate-limit bucket and one ban that hits everyone. Setting the key is therefore inevitable, which is why the gate must be correct before deploy.

**Other observations in this plug.** The XFF value is `[first | _]` then `String.split(",") |> List.first() |> String.trim()` — it uses the **leftmost** entry, which is the client-supplied, attacker-controlled end even with a well-behaved proxy. Trim is present (good); IPv6 with port (`[2001:db8::1]:443`) and IPv4 `1.2.3.4:5555` are not handled, and `IpHash.normalize/1` **raises** `ArgumentError` on unparseable input (`ip_hash.ex:48`) — so a bad header becomes a 500 rather than a fallback (**F11, Low**, dovetails with F2: once the gate is fixed, validate with `:inet.parse_address/1` and fall back to `conn.remote_ip`). Also `::ffff:1.2.3.4` and `1.2.3.4` hash differently, so dual-stack clients get two identities — normalise IPv4-mapped addresses (**F11**).

**The hash is computed exactly once** per request and is cheap (one HMAC-SHA256; the pepper lookup is an `:persistent_term`-backed `Application.get_env`). No double computation anywhere — `accela_ip_hash` is only read via `conn.private` and nothing else recomputes it. **Nothing to fix here.**

**F12 — Low.** `Plug.Conn.assign(:anonymous_ip_hash, ip_hash)` (`request_context.ex:25`) is **unused** (grep: no template or LiveView reads it) while `put_private/3` already exposes it to the Ash layer. Every assign is one template edit away from being rendered into HTML or a log line. *Fix:* delete the assign.

---

## 3. Router — self-registration of staff accounts

**F1 — High — registration is open; anyone can create an account on a staff-only system.**

The chain, verified end to end:

1. `user.ex:40` — `password :password` does **not** set `registration_enabled?`; the DSL default is `true` (`deps/ash_authentication/.../password/dsl.ex:95-100`).
2. `user.ex:201` — a `create :register_with_password` action exists (it even mints a JWT via `GenerateTokenChange`).
3. `router.ex:54` — `sign_in_route register_path: "/register"` mounts the register LiveView; `sign_in_route` mounts it whenever `register_path` is given, with no `registration_enabled?` check (`deps/ash_authentication_phoenix/.../router.ex:417`).
4. `router.ex:48` — `auth_routes AuthController, User, path: "/auth"` also exposes the plug route `POST /auth/user/register`.
5. `user.ex:57-59` — `bypass(AshAuthenticationInteraction) { authorize_if(always()) }` means no policy stands in the way of the create.

*Why it matters:* the module's own docstring says "Staff account… only staff authenticates", and there is no self-registration step in a staff-only model. An anonymous visitor gets a row in `users` and an authenticated session. **Honest scoping of impact:** this is *not* currently privilege escalation — `is_staff` defaults to `false` (`user.ex:77-81`), every privileged path checks `PolicyChecks.Staff` (`is_staff == true`), and rate limiting keys on the IP hash rather than on the actor, so a self-made account buys no moderation power and no rate-limit relief today. It escalates to **critical** the moment anything trusts mere authentication: the router already ships an empty `ash_authentication_live_session :authenticated_routes` and `LiveUserAuth` offers `:live_user_required` guidance (`router.ex:34-42`, `live_user_auth.ex:27-32`) — the natural next step ("staff page → `:live_user_required`") turns F1 into full unauthorized staff access. It also enables email squatting of moderator addresses (`unique_email` identity) and F7 enumeration. Confirmation does not help: `ConfirmationRequired` is only ever raised by OAuth2 strategies in this library version, so an unconfirmed password user signs in immediately.
*Fix (minimal):* `registration_enabled? false` in the password strategy, **remove `register_path: "/register"`** from `sign_in_route` (otherwise the LiveView route stays mounted), and delete the `create :register_with_password` action (or add `policy(action(:register_with_password)) do forbid_if(always()) end`). Onboard moderators with a `mix` task / seeds `authorize?: false`. Separately, add a `LiveUserAuth` action that checks `is_staff == true` and never gate staff pages on `current_user` presence alone.

**The rest of the routing surface is fine.** `sign_out_route` generates a `GET` confirmation page plus a `DELETE` handler, so logout-CSRF is properly prevented (`deps/ash_authentication_phoenix/.../router.ex:528-537`); `reset_route`/`confirm_route` are the standard flows; `sign_in_route`'s `on_mount: [{LiveUserAuth, :live_no_user}]` keeps signed-in users off `/sign-in`, `/register`, `/reset`.

---

## 4. Error handling — nothing found

`error_html.ex:21-23` and `error_json.ex:17-19` both return only `Phoenix.Controller.status_message_from_template/1` — no exception text, no changeset details, no request echo. `debug_errors` is set **only** in `dev.exs`, `stacktrace_depth` only in `dev.exs`, and prod leaves `render_errors` at the `config.exs` defaults, so exception pages and stack traces cannot reach a production client. `filter_parameters: ["password", "token"]` is set (`config.exs:9`). No information-disclosure finding in this category.

---

## 5. `/dev` (LiveDashboard) and `/admin` (AshAdmin) gating

**Gating is correct for a `MIX_ENV=prod` build, and there is no runtime path that enables it.** `Application.compile_env(:accela_imageboard, :dev_routes)` (`router.ex:82`, `router.ex:95`) is set in exactly one place — `config/dev.exs:57` (`dev_routes: true`). `config.exs`, `prod.exs` and `test.exs` do not set it, so a release compiled with `MIX_ENV=prod` compiles both blocks out and no runtime env var can bring them back. I found no other mount point for `ash_admin` or `live_dashboard`.

Two residual notes (Low, no finding number assigned since the gate itself holds):

- **The only accidental-enable path is building with the wrong `MIX_ENV`** (`MIX_ENV=dev mix release`, or an image that reuses a dev-compiled `_build`). Because the gate is compile-time with no runtime corroboration, consider a belt-and-braces guard in `runtime.exs`: `if config_env() == :prod and Application.compile_env(:accela_imageboard, :dev_routes), do: raise "dev_routes compiled into a prod build"`.
- **Even in dev both surfaces are completely unauthenticated**, and AshAdmin can write any resource — including flipping `is_staff`. On a shared dev/staging box that is a full compromise. If they are ever needed behind a proxy or tunnel, wrap the scopes in `Plug.BasicAuth` (the router's own comment says as much).

---

## 6. Session security, sign-out, CSRF

**F6 — Medium — the session cookie is not marked `secure`, and `force_ssl` exempts localhost.**
`endpoint.ex:7-12`: `store: :cookie, key: "_accela_imageboard_key", signing_salt: "Uot+Ee/z", same_site: "Lax"`. `http_only` defaults to `true` (good), `same_site: "Lax"` is a defensible choice here (it also blocks cookie-bearing cross-site POSTs to the `DELETE /sign-out` route). But `secure: true` is missing, and `prod.exs:15-21` exempts `hosts: ["localhost", "127.0.0.1"]` from the https redirect — so a request arriving with `Host: localhost` (a proxy that forwards whatever `Host` it is given will pass it) is served over plain http *and* may set/back-channel a session cookie containing the auth JWT.
*Fix:* add `secure: Mix.env() == :prod` (compile-time, standard in generated endpoints — dev keeps working over http://localhost) or read it from config; and drop the localhost host-exclusion in prod in favour of a `paths:` exclusion for health checks.

**Sign-out is correct — no finding.** `AuthController.sign_out/2` (`auth_controller.ex:71-78`) calls `clear_session(conn, :accela_imageboard)`, which is the AshAuthentication macro, not `Plug.Conn.clear_session/2` — it deletes remember-me cookies, **revokes bearer and session tokens** (`Helpers.revoke_session_tokens/2`) and then clears the session (`deps/ash_authentication_phoenix/.../controller.ex:276-283`). Combined with `store_all_tokens? true` and the `log_out_everywhere` add-on on password change, token revocation is genuinely wired up.

**CSRF is enabled** (`plug :protect_from_forgery`, `router.ex:10`) for the whole `:browser` pipeline, covering the `/auth` plug routes as well as controller routes; the masked token is exposed as `<meta name="csrf-token">` in the root layout. Note this does **not** protect against F1 — an attacker fetches a token from `GET /` and then posts to `/auth/user/register` with it.

`signing_salt: "Uot+Ee/z"` and `live_view: [signing_salt: "gD5oVa07"]` are public constants, which is fine (security rests on `SECRET_KEY_BASE`, correctly required from env at boot in `runtime.exs:73-82`, and `TOKEN_SIGNING_SECRET` likewise `System.get_env/1` + `raise`, read through the runtime `AshAuthentication.Secret` provider — no compile-time secret leak). Dev/test hard-coded secrets are environment-scoped only.

---

## 7. Staff enumeration

**F7 — Medium — `/register` confirms which emails exist.** `identities do identity(:unique_email, [:email]) end` (`user.ex:288`) plus the exposed register action means submitting an existing address returns the unique-identity error, which the register form renders. On an anonymous imageboard, confirming that `X@example.com` holds a staff account is exactly the reconnaissance step preceding credential phishing or a reset-token campaign. This is a *direct consequence of F1* — closing registration closes the leak.
*Fix:* `registration_enabled? false` + drop `register_path` (see F1). If self-service registration is ever wanted, prefer an invitation flow with a single generic "check your email" response.

**Reset/confirm flows: no enumeration in the reset path.** `request_password_reset_token` uses `RequestPasswordReset, action: :get_by_email` (`user.ex:250-262`), which returns `:ok` regardless of whether the address exists, and the reset view shows one message. `AuthController.failure/3` gives the generic `"Incorrect email or password"` for `{:password, _}` — but note the two `ConfirmationRequired`/`CannotConfirmUnconfirmedUser` clauses at `auth_controller.ex:35-53` match on `{_, reason}` and therefore sit *before* the password clause. Today they are unreachable for the password strategy (that error only comes from OAuth2), so they leak nothing — but they are a pre-positioned "an account with this email already exists" disclosure that becomes live the day a social/magic-link strategy is added. *Fix:* match `{{:password, _}, _}` first, or delete the OAuth-only clauses.

**F3 — Medium — reset and confirmation tokens are written to stdout.** Both senders are `IO.puts` stubs (`send_password_reset_email.ex:11-16`, `send_new_user_confirmation_email.ex:30-36`) — there is no mailer dependency. Those tokens are single-use credentials: anyone with log access (aggregator, support tooling, a shared container log, a leaked CI artifact) can reset any staff password or confirm any account. They also print relative, hard-coded paths. *Fix:* before exposing reset/confirm publicly, wire a real sender (Swoosh) and never log the token (`Logger.info("password reset requested for user #{user.id}")` only), or disable the `resettable` block and `confirm_route` until mail exists.

---

## Overall verdict

The foundations are better than a typical Phoenix scaffold: the header plug sets a genuinely strict CSP with clickjacking/COOP/COEP/CORP coverage and is immune to header injection, forged-request protection and the cookie's `http_only`/`same_site` are in place, sign-out does real token revocation, error rendering leaks nothing, and the `/dev`+`/admin` compile-time gate cannot be flipped on at runtime. Two issues need action before this is exposed to the internet. **F1 (open self-registration)** breaks the "staff-only accounts" premise at its root — it does not grant moderation powers today only because `is_staff` defaults to false and every privileged check tests it, so it is one `:live_user_required` away from being critical; closing it costs one DSL line plus removing `register_path`. **F2 (`trusted_proxies` treated as a boolean)** is a latent identity-forgery flaw in the one computation the entire anti-abuse design rests on: the code will silently trust `X-Forwarded-For` from anyone the moment an operator configures the value the docstring tells them to configure, and if they don't, every visitor collapses into a single poster hash behind the proxy. Fix F1 and F2 first, then the medium cluster (log-leaked reset tokens, the CSP-blocked inline script and its `Mix.env()`-chosen variant, the missing `secure` cookie flag), and treat the low items as ordinary hardening backlog.
