# Security audit — Boards domain (Accela Imageboard Engine)

Scope: the public content domain — `lib/accela_imageboard/boards.ex`, `boards/{board,thread,post,media}.ex`,
`boards/changes/{set_poster_hash,rate_limit,banned_poster}.ex`, `boards/checks/{thread_open,board_open}.ex`,
`lib/accela_imageboard/rate_limits.ex`, plus `test/accela_imageboard/{boards_test,rate_limit_test}.exs` for the
intended invariants. Adjacent code (`moderation/*`, `security/ip_hash.ex`, `plugs/request_context.ex`, migrations)
was read where it decides a Boards finding.

Method: static review only — no code was modified and no test was run. Claims about framework behaviour are
backed by reading the pinned dependencies:

- `deps/ash/documentation/topics/security/sensitive-data.md:10-12` — `public?` only governs API extensions; it is
  irrelevant to in-code reads such as `Ash.read/2`.
- `deps/ash/lib/ash/resource/transformers/default_accept.ex:20-31` — for non-embedded resources the resource
  `default_accept` is `[]`, so an action without `accept` accepts **no** attributes.
- `deps/ash/lib/ash/domain/dsl.ex:73-79` — domain `authorization.authorize` defaults to `:by_default`, so omitting
  `authorize?:` at a call site still runs policies.
- `deps/ash/lib/ash/changeset/changeset.ex:2995-3012` — an upsert with no `upsert_fields` sets *every*
  explicitly-changing attribute on conflict.
- `deps/hammer/lib/hammer/ets/fix_window.ex:139-146` — default ETS algorithm is a fixed window keyed
  `{key, window}` with `expires_at` at the window edge.
- `deps/hammer/lib/hammer/ets.ex:185-188,233-256` — buckets live in a node-local ETS table, cleaned on a timer
  (`clean_period: 10 min`, configured at `lib/accela_imageboard/application.ex:15`).

Severities assume the eventual web layer renders board content to anonymous visitors (today it does not — the only
route renders a static page, `lib/accela_imageboard_web/controllers/page_controller.ex:4-6`).

---

## 1. Authorization gaps

### A1 — HIGH — soft-deleted posts are still publicly readable

Location: `lib/accela_imageboard/boards/post.ex:68` (`defaults([:read])`), `post.ex:24-26` (`authorize_if(always())`),
`post.ex:70-74` (`read :in_thread`), `thread.ex:52-53` (`has_many :posts`), `thread.ex:89-92` (aggregates).

What is wrong: the `is_nil(deleted_at)` filter lives **only** in the secondary `:in_thread` action. The primary
`:read` action has no filter, and the `Thread.posts` relationship declares no `filter`, so both `Ash.read(Post)` and
`thread.posts` return moderated content. The `post_count` / `last_post_at` / `first_post_at` aggregates count
deleted posts as well.

Why it matters: `moderate` (`post.ex:87-91`) is the only takedown mechanism in the domain ("content disappears but
rows remain for audit"). It is cosmetic against every read path except the one callers are not forced to use, so the
obvious thread view — loading the `posts` relationship — keeps serving removed content, and the removed post's media
stay reachable (see D2).

Minimal fix: put `filter(expr(is_nil(deleted_at)))` on the primary `:read` action (and/or on the `:posts`
relationship and the aggregates), and give staff an explicit unfiltered read action for moderation views.

### A2 — MEDIUM — `hidden` boards are readable by anyone

Location: `lib/accela_imageboard/boards/board.ex:25-28` (`action_type(:read)` → `authorize_if(always())`), filter only
at `board.ex:58-62` (`read :list_public`); `thread.ex:18-20` (Thread read policy).

What is wrong: `hidden` ("Soft-hide a whole board without destroying data", `board.ex:45-46`) is enforced only in
`:list_public`. The default `:read` action returns hidden boards, `Board.threads` (`board.ex:49-53`) uses that same
read, and the `Thread` read policy has no `board.hidden` condition — so a hidden board's threads and posts remain
readable once an id is known. Note the code comment at `board.ex:20-21` claims hidden boards are only readable
"by staff"; in fact every reader can read them.

Why it matters: `hidden` is a staff takedown tool for a whole board (the thing you reach for before deleting
evidence). It currently only removes the board from one listing while the content stays public, and board ids leak
via links, reports and screen captures.

Minimal fix: move `hidden == false` into the primary `Board` read action and add `board.hidden == false` to the
`Thread` read action; keep an explicit staff-only unfiltered read.

### A3 — LOW — TOCTOU on lock / archive / hide

Location: `lib/accela_imageboard/boards/checks/thread_open.ex:23-47`, `lib/accela_imageboard/boards/checks/board_open.ex:12-33`.

What is wrong: both checks issue a separate `Ash.read(authorize?: false)` during authorization; the insert happens
afterwards. A post can land in a thread that staff lock or archive — or on a board that becomes hidden/staff-only —
between the check and the insert. `archived`/`locked` are only re-read on the next request.

Why it matters: small window and the impact is a single post (no integrity loss beyond that), but the check is not a
guard on the write it authorizes.

Minimal fix: re-assert `locked == false and archived == false` in a `before_action` that runs immediately before the
insert (or make the parent state part of an atomic guarded write).

### Verified as *not* vulnerable in this category

- **No mass-update / update-defaults abuse.** Every write action has an explicit `accept` list: `post.ex:83`,
  `thread.ex:74`, `thread.ex:84`, `board.ex:66`, `board.ex:71`, `media.ex:66`. `update :post_bump` (`thread.ex:77-80`)
  has *no* `accept`, but Ash's `default_accept` is `[]` for non-embedded resources, so it can only set `bumped_at`
  through its `set_attribute` change. (Still worth writing `accept([])` explicitly as intent.)
- **No N+1 / relationship injection.** There is no `manage_relationship` anywhere in `lib/` or `test/`, no nested
  relationship writes, and no `accept :*`. Passing a nested `thread`/`post` map yields `NoSuchInput`.
- **No anonymous path to a staff action.** `:moderate`/`:destroy` (post), `:post_bump`/`:staff_update`/`:destroy`
  (thread), `:create`/`:update`/`:destroy` (board), `:attach`/`:detach` (media) all resolve through
  `AccelaImageboard.PolicyChecks.Staff`, whose `match?/3` only succeeds on `%{is_staff: true}`
  (`lib/accela_imageboard/policy_checks/staff.ex:13-14`); a `nil` actor fails. Unmatched actions are default-deny.
- **No silent policy bypass from a missing `authorize?`.** The `Boards` domain does not override `authorization`, so
  Ash's `:by_default` applies and `Ash.read/Ash.create` without `authorize?:` still run policies. The only
  `authorize?: false` calls are the three internal checks above and the tests. `Ash.Domain.Info.require_actor?` is
  false, which is required for anonymous posting.
- No bulk actions, no `Ash.update` with a changeset built from params anywhere in `lib/`.

---

## 2. Anonymous identity flow

### B1 — MEDIUM — `Thread.create` records no poster identity and does not fail closed

Location: `lib/accela_imageboard/boards/thread.ex:66-75`, `thread.ex:69-70` (comment), `boards/changes/banned_poster.ex:19-22`.

What is wrong: `Thread.create` has `RateLimit` + `BannedPoster` but **no** `SetPosterHash`, and `Thread` has no
`poster_hash` attribute at all, even though the comment at `thread.ex:69-70` states that "OP identity, rate limit and
ban check are all keyed off the anonymous poster's IP hash". `BannedPoster` treats a missing hash as "not banned"
(`check_ban(nil, changeset) → changeset`), so a thread created without context is silently unattributed *and*
unchecked — a post in the same situation is rejected because `SetPosterHash` errors (`set_poster_hash.ex:28-31`).

Why it matters: the domain loses its "no unattributed content" invariant on exactly the action an attacker would
pick to shed attribution, and staff lose the data needed to tie an OP thread to a banned identity.

Minimal fix: add `attribute(:poster_hash, :string, allow_nil?: false, public?: false)` to `Thread` and
`change(AccelaImageboard.Boards.Changes.SetPosterHash)` to `:create`.

### B2 — MEDIUM — the identity is computed but never wired into the Ash context

Location: `lib/accela_imageboard_web/plugs/request_context.ex:21-25`.

What is wrong: the plug stores `:accela_ip_hash` in `conn.private` and `:anonymous_ip_hash` in assigns, and
**nothing in the codebase reads either** (a grep for `accela_ip_hash|anonymous_ip_hash` matches only the plug
itself). There is no helper that turns a conn or socket into `context: %{anonymous: %{ip_hash: …}}`, and no
board-facing view exists yet, so the intended end-to-end flow is not implemented.

Why it matters: every future call site must re-invent the wiring. The single correct implementation reads
server-side state (`conn.private`); the plausible wrong ones read the hash from params, or from a socket assign fed
by client input — either turns into poster-hash spoofing, i.e. ban evasion plus unlimited rate-limit buckets.

Minimal fix: add one function, e.g. `AccelaImageboard.Security.Anonymous.context(conn_or_socket)`, that reads only
`conn.private[:accela_ip_hash]`, and use it for every `Post`/`Thread`/`Report` create.

### Verified: no path turns client input into the poster hash

- `poster_hash` is absent from every `accept` list, so supplying it raises `NoSuchInput`
  (covered by `test/accela_imageboard/boards_test.exs:70-81`).
- `SetPosterHash` writes with `force_change_attribute` from `changeset.context` only
  (`boards/changes/set_poster_hash.ex:18-31`), and errors when the context is missing.
- `Report.create` mirrors the pattern with `reporter_hash` (`lib/accela_imageboard/moderation/report.ex:52-57`);
  `Ban.poster_hash` is written by staff only (`moderation/ban.ex:24-28,60-63`).
- `SetPosterHash`/`RateLimit`/`BannedPoster` are present on `Post.create` (`post.ex:79-81`) and, except for
  `SetPosterHash`, on `Thread.create` (`thread.ex:71-72`); `Report.create` has `SetPosterHash` + `RateLimit` but no
  `BannedPoster` (reported as E1).

---

## 3. Rate limiting

### C1 — MEDIUM — the limiter is per-node, so limits multiply by cluster size

Location: `lib/accela_imageboard/rate_limits.ex:19-32` (`use Hammer, backend: :ets`), `lib/accela_imageboard/application.ex:12,15`
(`DNSCluster` and the `RateLimits` child), `deps/hammer/lib/hammer/ets.ex:225-230`.

What is wrong: buckets live in a node-local ETS table created by the limiter process. With N nodes behind the load
balancer the effective limit is N× and a given poster's requests are spread across independent buckets.

Why it matters: the documented limits ("20 posts / 5 min per poster", `rate_limits.ex:19-23`) are not what a
clustered deployment enforces, and how much protection applies depends on load-balancer stickiness.

Minimal fix: document the limiter as best-effort per node, or move the counter to a shared backend (`hammer`
supports Postgres/Redis) if the limits are meant to bound abuse.

### C2 — MEDIUM — shared `"unknown"` bucket, charged before identity is validated

Location: `lib/accela_imageboard/boards/changes/rate_limit.ex:28-33`; ordering at `post.ex:79-81` and `thread.ex:71-72`.

What is wrong: the subject is `get_in(context, [:anonymous, :ip_hash]) || (changeset.data && changeset.data.id && to_string(changeset.data.id)) || "unknown"`.
On a create, `changeset.data.id` is always `nil` (defaults are applied to `changeset.attributes`, not to `data`), so
every context-less create shares the single key `{:post_create, "unknown"}`. The change is also registered *first*,
so a token is consumed before `BannedPoster`, `SetPosterHash` or attribute validations can reject the request. On an
update the fallback would key on the record id — a different identity space from create.

Why it matters: any code path that forgets the context (a staff back-office post, the un-wired flow in B2, a future
job) both draws from one shared bucket and can drain it, locking out every other context-less caller; and quota is
burned by requests that are ultimately refused, which makes a rate-limit error the reported symptom for unrelated
validation failures.

Minimal fix: deny when the hash is absent (the same fail-closed rule as `SetPosterHash`) instead of falling back to
a shared key; drop the `changeset.data.id` fallback or make the subject explicit per action.

### C3 — MEDIUM (HIGH if `:trusted_proxies` is ever set) — client-chosen identity via `X-Forwarded-For`

Location: `lib/accela_imageboard_web/plugs/request_context.ex:28-43`.

What is wrong: `trusted = Application.get_env(:accela_imageboard, :trusted_proxies, [])` is only tested for
non-emptiness (`if trusted != []`); the immediate peer's `conn.remote_ip` is never checked against the list, and the
plug takes the **leftmost** `X-Forwarded-For` hop — the one the client itself supplies.

Why it matters: if that option is ever configured, any client controls its entire identity. A fresh header value per
request yields a fresh poster hash, so (a) the rate limiter never fires and one ETS bucket is created per request
(retained until the window edge, cleaned every 10 minutes per `application.ex:15`), and (b) bans are bypassed
entirely. It also lets an attacker impersonate a *known* hash if one becomes known (see D1). Today the option is
unset — `config/runtime.exs` never reads a `TRUSTED_PROXIES` variable, so this is a dormant footgun rather than a
live bug, and the plug's moduledoc overstates the protection.

Minimal fix: only honour the header when `conn.remote_ip` is in the configured proxy list, and take the **rightmost**
hop that is not itself a trusted proxy; wire the list to an env var so enabling it is a conscious act.

### C4 — LOW — fixed-window boundary burst; no per-thread/board dimension

Location: `deps/hammer/lib/hammer/ets/fix_window.ex:139-146` (default algorithm), `rate_limits.ex:19-23`.

What is wrong: the default `:fix_window` algorithm keys on `{key, window}` with `expires_at` at the window edge, so a
poster can emit up to 2× the limit within a few seconds across a boundary (documented in Hammer's own moduledoc). The
bucket is also per action rather than per board/thread, so all users behind one NAT/CGNAT address share a bucket.

Why it matters: minor for an imageboard, but it means the configured limit is not a hard bound.

Minimal fix: `algorithm: :sliding_window` if the double burst matters; otherwise document it.

### Answer to the "attacker-controlled bucket key" question

No: the key is `{action_atom, subject}` where `subject` derives from the HMAC'd client IP (or the `"unknown"`
constant) and never from a request parameter, and `RateLimit.init/1` rejects any key outside
`%{thread_create: 1, post_create: 1, report_create: 1}` (`rate_limit.ex:18-25`). The residual key-level weaknesses
are that `subject` can be *absent* (C2) or *attacker-chosen at the IP level* (C3), and that key space is unbounded
(one bucket per new IP/window, retained for the window).

---

## 4. Data exposure

### D1 — MEDIUM — `public?: false` does not hide `poster_hash`

Location: `lib/accela_imageboard/boards/post.ex:46-50`; same pattern at `moderation/report.ex:45` (`reporter_hash`)
and `boards/media.ex:49` (`sha256`).

What is wrong: Ash's guidance is explicit that "if you are working with Ash in code, reading a resource, for example
using `Ash.read/2`, the public/private status of an attribute is not relevant"
(`deps/ash/documentation/topics/security/sensitive-data.md:10-12`); `public?` only governs API extensions
(AshJsonApi/AshGraphql) and field-level input/filter APIs. None of the four resources declares a field policy, so
every `Ash.read(Post)` returns the full struct **including `poster_hash`**, and `Media` reads return `sha256`.

Why it matters: `poster_hash` is the ban key and the pseudonymous poster identity. Disclosing it lets any visitor
link all posts by one IP across all boards (deanonymisation), correlate a banned identity's history, and — combined
with C3 — target or impersonate an identity. The attribute's own description says "never a raw IP", which is true,
but the hash is still a stable pseudonym. There is no leak surface today (no board views, no JSON API, AshAdmin only
under `dev_routes`), so this is latent — precisely the kind of exposure a template (`{post.poster_hash}`) or a
`Map.from_struct/1` serializer introduces later.

Minimal fix: declare field policies on `Post`/`Report` (and `Media` for `sha256`), e.g.

```elixir
field_policies do
  field_policy :poster_hash do
    authorize_if AccelaImageboard.PolicyChecks.Staff
  end
end
```

and consider `sensitive?: true` so the value is redacted in logs, traces and `inspect/1` output.

### D2 — LOW — media of deleted posts and hidden boards stay fetchable, storage key included

Location: `lib/accela_imageboard/boards/media.ex:23-25` (read → `authorize_if(always())`), `media.ex:37-42`
(`storage_key` is `public? true`).

What is wrong: `Media` reads are unconditional — no condition on the parent post's `deleted_at`, the board's
`hidden`, or `staff_only_threads`. Removing a post or hiding a board therefore leaves its images reachable by id or
storage key, and the storage key is exposed to clients by design (the serving controller needs it).

Why it matters: takedown of an illegal or doxxing image is incomplete; the file is still served as long as the key is
known or guessable-and-enumerable via a media read.

Minimal fix: filter `Media` reads on the parent post's state (or enforce it in the media-serving controller by
loading the post and checking `deleted_at`/`hidden`/board policy), instead of serving on a bare key lookup.

### No issue found for bans

Every `Ban` action — including the `:read`, `:active` and `:check` reads — is gated by `policy always() →
PolicyChecks.Staff` (`lib/accela_imageboard/moderation/ban.ex:24-28`), so ban rows, reasons, expiry and the
`issued_by` link are staff-only through normal reads. `Ban.poster_hash` is private by default.

---

## 5. `BannedPoster` fail-closed logic and its `authorize?: false` read

### E1 — LOW — a missing identity is treated as "not banned"

Location: `lib/accela_imageboard/boards/changes/banned_poster.ex:19-22` (`check_ban(nil, changeset) → changeset`).

What is wrong: the check is only fail-closed for *errors*, not for a *missing subject*. `Thread.create` is protected
only by `BannedPoster` + `RateLimit` (B1), and `Report.create` has no `BannedPoster` at all
(`moderation/report.ex:52-57`), so a banned poster can still open threads from a context-less path and can always
file reports (bounded only by 10 reports / 15 min).

Why it matters: bans are the primary abuse control in an accountless imageboard; a code path that does not carry the
context silently disables enforcement instead of denying.

Minimal fix: make `check_ban(nil, changeset)` add the error, and add `change(BannedPoster)` to `Report.create`.

### E2 — LOW — a non-binary hash raises instead of denying

Location: `banned_poster.ex:24-25` versus `set_poster_hash.ex:20-21`.

What is wrong: `BannedPoster` matches only `nil` and `is_binary/1`, while `SetPosterHash` deliberately accepts a map
form `%{"hash" => _}`. If anything ever supplies that shape, `BannedPoster` raises `FunctionClauseError` (HTTP 500 /
LiveView crash) instead of failing closed, and `RateLimit` would use the whole map as a bucket key. Symmetrically,
`set_poster_hash.ex:20` — `changeset.context[:anonymous][:ip_hash]` — raises if `context[:anonymous]` is a non-map
(`Access.get/2` has no clause for, say, a binary).

Why it matters: the failure mode is a crash rather than a denial, in the code path the domain relies on for its
"fail closed" guarantee.

Minimal fix: normalise the identity in one shared private helper returning `{:ok, hash} | :error`, and consume it
from all three changes.

### E3 — INFO — the `authorize?: false` read is not exploitable

The query at `banned_poster.ex:36-47` is built with a pinned, server-derived value
(`expr(poster_hash == ^poster_hash and (is_nil(expires_at) or expires_at > ^now))`), returns only a boolean, and
never exposes ban rows to the caller; no user input reaches the filter, and the value cannot be chosen by the
client unless C3 is enabled. Bypassing the staff-only policy here is the intended design, not a gap. The one real
consequence of `{:error, _} -> true` is availability: any failure of the `Ban` read denies *all* posting, which is a
reasonable trade-off for an imageboard but should be monitored.

Recommendation: route this through the existing purpose-built `Ban :check` action (`moderation/ban.ex:53-58`,
`get? true`, argument `poster_hash`) instead of re-implementing the filter, so the "active ban" rule lives in exactly
one place.

---

## 6. Crash / DoS from input

### F1 — MEDIUM — anonymous writers can store unbounded strings

Location: `lib/accela_imageboard/boards/post.ex:44` (`:name`), `lib/accela_imageboard/boards/thread.ex:36-37`
(`:subject`, `:name`), accepted for anonymous create at `post.ex:83` and `thread.ex:74`; columns are bare `text`
(`priv/repo/migrations/20261120234736_initialize.exs:84-85`, `:124-125`).

What is wrong: `body` is bounded (`max_length: 10_000`, `post.ex:42`) but `name` and `subject` have no
`constraints: [max_length: …]`, and the database has no length constraint either, so a single request can store a
multi-megabyte nickname or subject. `config/config.exs` already sets
`config :ash, default_string_length_count: :codepoints` so an added constraint would genuinely bound stored bytes.

Why it matters: within one rate-limit window an anonymous poster can write megabytes per row; `subject`/`name` are
rendered in every thread listing (board index, thread header), so the cost is paid on every page view by every
visitor — cheap storage/render amplification, the classic unbounded-imageboard-nickname problem. The rate limiter
does not prevent it (20 posts / 5 min is still 5× the limit per window in the fictional worst case).

Minimal fix: `attribute(:name, :string, public?: true, constraints: [max_length: 100])` on `Post` and `Thread`, and
`constraints: [max_length: 200]` on `Thread.subject`. Lower priority, same shape: `Media.original_filename` /
`content_type` (`media.ex:43-45`) and `Board.slug/name/description/rules` (`board.ex:38-41`, staff-only).

### F2 — LOW — `IpHash.hash/1` raises on a malformed client IP

Location: `lib/accela_imageboard/security/ip_hash.ex:36-40` (raise), called unguarded at
`lib/accela_imageboard_web/plugs/request_context.ex:21`.

What is wrong: `normalize/1` raises `ArgumentError` for anything that is not a parseable IP; the plug does not
rescue. With C3's header path enabled, `X-Forwarded-For: javascript:` turns every request into a 500 with a stack
trace in the log; `hash/1` also raises for a non-binary, non-tuple argument.

Why it matters: unauthenticated 5xx generation and log noise; it also means a single malformed header breaks the
whole request rather than degrading to "unattributed", which is the fail-closed behaviour the domain expects.

Minimal fix: rescue `ArgumentError` and fall back to `conn.remote_ip` (or reject the header value and treat the
request as unattributed, in which case `SetPosterHash` will refuse the create).

### F3 — LOW — missing indexes on the anonymous hot path

Location: `priv/repo/migrations/20261120234736_initialize.exs:13,25` (`bans`), `:85-88` (`posts.thread_id`),
`:134-139` (`threads.board_id`), `:47-52` (`media.post_id`). The only indexes in the schema are the unique ones on
`boards.slug`, `media.sha256`, `media.storage_key`, `users.email`.

What is wrong: `bans.poster_hash` / `bans.expires_at` are unindexed, so the `BannedPoster` query
(`banned_poster.ex:36-47`) is a full scan of `bans` on **every** anonymous post *and* thread creation. Foreign-key
constraints do not create indexes in PostgreSQL, so `thread.posts` / `by_filter(thread_id)` and `board.threads` are
full scans of `posts` and `threads` as well.

Why it matters: attacker-driven full scans of tables that grow with user content; the ban check turns the cheapest
write path into an O(bans) operation, and every thread view into an O(posts) one. This is the kind of amplification
that turns a small flood into a database incident.

Minimal fix: `create index(:bans, [:poster_hash])` (optionally `[:poster_hash, :expires_at]`),
`create index(:posts, [:thread_id, :inserted_at])`, `create index(:threads, [:board_id, :inserted_at])`,
`create index(:media, [:post_id])`, `create index(:reports, [:post_id])`.

### F4 — INFO — the limiter runs after body parsing

`RateLimit` executes inside the Ash action (`rate_limit.ex:27-46`), i.e. after `Plug.Parsers` has read and decoded
the body, so it does not bound body-size or JSON-depth floods. Set explicit `length:` limits in the endpoint's
parser options if that matters; today `lib/accela_imageboard_web/endpoint.ex` relies on the defaults.

---

## 7. Lock / archived / hidden enforcement elsewhere

### G1 — LOW — nothing ever bumps a thread, and `post_bump` is staff-only

Location: `lib/accela_imageboard/boards/thread.ex:28-30` (policy), `thread.ex:77-80` (action).

What is wrong: `:post_bump` is in the staff-only policy, and `Post.create` never calls it, so `bumped_at` never
reflects activity and the documented "archived threads … stop bumping" invariant has no enforcement point (archived
threads are instead fully read-only via `ThreadOpen`). `post_bump` itself is safe against mass-assignment because
Ash's `default_accept` is `[]`, but the empty `accept` should be explicit.

Why it matters: logic, not a hole — but an imageboard whose ordering never changes is broken, and the moment someone
"fixes" it by calling `post_bump` from an anonymous post path, the missing `archived`/`locked` guard in that action
becomes a moderation bypass.

Minimal fix: either delete the action and the field, or call it from the post-create flow with `authorize?: false`
after the post is committed, refusing when `archived == true`, and write `accept([])`.

### G2 — LOW — `Media.attach` upsert can re-point an existing media row

Location: `lib/accela_imageboard/boards/media.ex:62-67`.

What is wrong: `upsert?(true)` with `upsert_identity(:sha256)` and no `upsert_fields`, so a second `attach` of an
existing `sha256` overwrites that row's `storage_key`, `post_id`, `content_type`, `original_filename` and
`byte_size` (Ash sets every explicitly-changing attribute on conflict,
`deps/ash/lib/ash/changeset/changeset.ex:2995-3012`). The action is staff-only today, and its `accept` list takes
`post_id`, `sha256` and `storage_key` straight from params (`media.ex:66`).

Why it matters: the moduledoc (`media.ex:28-29`) states the web layer will attach media "as part of the (authorized)
post flow". That flow runs as an anonymous actor, so it will need `authorize?: false` — at which point this becomes
an anonymous primitive to reassign any media row to your own post, or to pre-claim a `storage_key`, and to poison
the dedupe/identity index.

Minimal fix: `upsert_fields([])` so a duplicate `sha256` is a no-op that returns the existing row, and take the post
id from the already-authorized post rather than from params.

### G3 — INFO — `media.post_id` has no `on_delete`

`priv/repo/migrations/20261120234736_initialize.exs:74-80` creates the FK without `on_delete`, so
`Ash.destroy(post)` (`post.ex:93-95`, staff-only) fails with a foreign-key error whenever media exist. Content
removal effectively depends on `moderate`, whose read-side leak is A1 — so the two interact: the only action that
works is the one whose result is still publicly visible.

---

## Category scorecard

| Audit category | Result |
| --- | --- |
| 1. Authorization gaps (staff-only bypass, mass-update, update defaults, `manage_relationship` injection) | **A1 (high), A2 (medium), A3 (low)**; no bypass, no mass-assignment, no relationship injection |
| 2. Client input → `poster_hash`; missing `SetPosterHash`/`RateLimit`/`BannedPoster` | **B1, B2 (medium)**; no client-input path found; `Report.create` lacks `BannedPoster` (E1) |
| 3. Rate-limit races / ETS key weaknesses / `simulated`-unknown fallback | **C1, C2, C3 (medium), C4 (low)**; bucket key content is not attacker-controlled |
| 4. Data exposure | **D1 (medium), D2 (low)**; bans correctly staff-only |
| 5. `BannedPoster` fail-closed + `authorize?: false` read | **E1, E2 (low)**; the `authorize?: false` read itself is not exploitable (E3) |
| 6. Crash / DoS from input (unbounded strings, missing `max_length`) | **F1 (medium), F2, F3 (low), F4 (info)** |
| 7. Lock/archived/hidden on other actions, TOCTOU | **G1, G2 (low), G3 (info)**, plus A3 |

---

## Overall verdict

The authorization model is genuinely well built for the parts that are hardest to get right: policies are
default-deny per action, every write action carries an explicit `accept` list (so there is no mass-assignment and no
managed-relationship injection anywhere in the domain), the domain runs Ash in `:by_default` authorization mode so a
forgotten `authorize?:` cannot silently disable policies, and the poster hash is provably not settable from client
input — a clean result on audit points 1, 2 (input side) and 5. The weaknesses sit at the **edges of the read paths
and in the identity plumbing**: the two soft-hide/soft-delete controls are enforced only on the secondary read
actions, so hidden boards and moderated posts remain public through the primary reads and through
`board.threads`/`thread.posts` (A1, A2); `public?: false` does not keep `poster_hash` out of in-code reads (D1);
thread creation stores no identity and does not fail closed (B1); and the identity the plug computes is not yet
connected to anything, so the safe wiring will be re-invented per call site (B2). Rate limiting derives its keys
soundly but is per-node, has a shared `"unknown"` bucket that is charged before identity validation, and inherits a
dormant full identity-spoofing primitive in the `X-Forwarded-For` handling (C1–C3). Fixing A1, A2, B1 and D1 is
roughly a dozen lines and would take the domain from "correct-looking" to "correct" against its own documented
invariants; none of the findings is currently exploitable end to end only because the application has no
board-facing views yet, which also means the cheap fixes should land before those views are written.
