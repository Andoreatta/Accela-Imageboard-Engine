# Domain hardening — remediation notes (boards/auth findings)

Scope: findings assigned to the domain agent (`lib/accela_imageboard/**`, `test/**`).
Web-layer items (route removal for `/register`, cookie/CSP/XFF config, `runtime.exs`
`IP_HASH_SECRET` wiring) were **not** touched — another agent owns `config/` and
`lib/accela_imageboard_web/`.

## What was fixed

| Finding | Fix | Where |
| --- | --- | --- |
| A1 (high) — soft-deleted posts publicly readable | `is_nil(deleted_at)` moved onto the **primary** `read` action, the `Thread.posts` relationship and the `post_count`/`first_post_id`/`last_post_id` aggregates; new staff-only `read :moderation_queue` returns moderated content | `boards/post.ex`, `boards/thread.ex` |
| A2 (medium) — hidden boards readable | Primary `Board.read` filters `hidden == false`; new staff-only `Board.read :staff_read`; `Thread.read` filters `board.hidden == false` with staff-only `Thread.read :staff_read` | `boards/board.ex`, `boards/thread.ex` |
| F-18 (medium) — Staff check accepts bare maps | `match?/3` pattern-matches `%AccelaImageboard.Accounts.User{is_staff: true}` | `policy_checks/staff.ex` |
| Web #1 (high, domain half) — staff self-registration | `policy(action(:register_with_password)) do forbid_if(always()) end`; AshAuthentication's internal strategy calls still pass via the `AshAuthenticationInteraction` bypass (tested) | `accounts/user.ex` |
| F-09 (medium) — IPv6 representation evasion | `IpHash` normalizes: IPv4-mapped IPv6 collapsed to IPv4, zone ids (`%eth0`, `%25eth0`) stripped, canonical lowercase/compressed form via `:inet.ntoa/1` | `security/ip_hash.ex` |
| F-12 (medium) — audit attribution forgery | `:staff_id` removed from the `:log` accept list; `Moderation.Changes.StaffActor` force-sets it from the actor and errors without one | `moderation/action_log.ex`, `moderation/changes/staff_actor.ex` |
| F-13 (medium) — audit log never written | `Moderation.Changes.LogAction` appends an entry after `Post.moderate`, `Ban.ban`, `Ban.lift`, `Thread.staff_update` and each `Report` transition (action name, target type/id, staff from actor, changed attribute **names** only); a failed audit write fails the action | `moderation/changes/log_action.ex` + the four resources |
| F-15 (medium) — `Ban.read :check` was `get?` over a non-unique column | plain filtered read; duplicate active bans no longer raise; documented fail-closed contract | `moderation/ban.ex` |
| F-17 (medium) — `Report.create` accepts arbitrary `post_id` | `Moderation.Changes.ExistingPost` fails closed unless the id resolves to a live post (the lookup uses the filtered primary read, so moderated posts are refused too) | `moderation/changes/existing_post.ex`, `moderation/report.ex` |
| F-01/F-02/F-03/F-11 (low) — PBKDF2 hardening | `valid?/2` nil clauses (return `false`, never raise), iteration floor 100 000 + ceiling 10 000 000 on decode, key length bounds, `Base.decode64` malformed input returns `false`, `hash/1` rescue narrowed to `ArgumentError`/`ErlangError` and documented; stored format unchanged | `auth/pbkdf2_hash_provider.ex` |
| F-05 (low) — empty token signing secret | `secret_for/4` returns `:error` unless the secret is a non-empty binary | `secrets.ex` |

## Incidental fixes found while testing

* **`Report` transitions never changed state.** `update(:accept | :reject | :resolve)`
  declared `transition_state` only in the `state_machine` block, which is
  declarative — the actions had no change, so `state` stayed `:open`. Added
  `change(transition_state(...))` to each action; `accepted.state == :accepted`
  is now asserted in `test/accela_imageboard/moderation_test.exs`.
* **`posts` has no timestamp column**, so `Post.read :in_thread` sorted by a
  non-existent `inserted_at` and the `first_post_at`/`last_post_at` aggregates
  could never be loaded. Sorting now uses `id` (uuid_v7 → time ordered) and the
  aggregates were renamed to `first_post_id`/`last_post_id`, which return the
  id of the first/last visible post.

## Needs the main agent

1. **Migration (optional, schema-level):** add `inserted_at`/`updated_at` to
   `posts` if real timestamps are wanted; then `first_post_id`/`last_post_id`
   can become `first_post_at`/`last_post_at` again. Nothing in the web layer
   references the aggregates today, so the rename is safe now.
2. **Web agent:** `board.threads` goes through the Thread primary read, so a
   staff console must list a hidden board's threads with
   `Thread |> Ash.Query.filter(board_id == ^board.id) |> Ash.read(action: :staff_read, actor: staff)`.
3. **Web agent:** `AshAuthentication` registration now depends entirely on the
   bypass; removing the `/register` route is still the right end-user fix.
4. **Not fixed (out of assigned scope):** `Ban.ban` still accepts `issued_by_id`
   from params (same forgery class as F-12 for bans — derive it with
   `Moderation.Changes.StaffActor, attr: :issued_by_id`); `Media` policy/`attach`
   issues (boards-audit D2/G2); `post_bump` is staff-only although anonymous
   posts should bump; `posts.inserted_at` above; sobelow reports a missing CSP in
   `lib/accela_imageboard_web/router.ex` (web agent's area; `mix check` runs
   `sobelow` without `--exit`, so it does not fail the gate).
