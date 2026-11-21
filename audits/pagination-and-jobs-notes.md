# Performance, pagination and job infrastructure (phase 2)

Scope: `lib/accela_imageboard/**` (except `media/**` and `boards/media.ex`), `priv/**`,
`config/**`, `test/accela_imageboard/**`. Nothing in `lib/accela_imageboard_web/**`,
`assets/**` or `mix.exs` was touched.

## 1. Indexes for the hot read paths

Declared in the resources (`custom_indexes` section, the Ash source of truth) and applied
by `priv/repo/migrations/20261121004530_add_indexes_for_hot_paths.exs`
(`mix ash.codegen add_indexes_for_hot_paths`).

| Index | Serves |
| --- | --- |
| `threads (board_id, pinned, bumped_at)` | the board thread list: `WHERE board_id = ? ORDER BY pinned DESC, bumped_at DESC` |
| `posts (thread_id, id)` | a thread's posts: `WHERE thread_id = ? ORDER BY id` |
| `bans (poster_hash, expires_at)` | ban checks: `poster_hash = ? AND (expires_at IS NULL OR expires_at > now())` |
| `reports (post_id)` | "reports for this post" |
| `reports (state)` | staff triage queue |
| `media (post_id)` | media of a post — added as raw SQL in the migration because `Boards.Media` is owned by another agent (see the migration moduledoc; delete that statement once `custom_indexes do index([:post_id]) end` lands in the resource) |

Deliberate deviations from the task's list, and why:

* **`posts (thread_id, inserted_at)` → `posts (thread_id, id)`.** `posts` has no
  `inserted_at` column in this schema, and adding one would backfill every existing row with
  the migration timestamp (worse than useless for ordering). Ids are `uuid_v7`, i.e. time
  ordered, so `id` *is* the insertion order — the same conclusion phase 1 reached for
  `first_post_id`/`last_post_id`.
* **No separate `threads (board_id)` / `posts (thread_id)` / `bans (poster_hash)` indexes.**
  A btree with those columns first serves every query the single-column index would
  (`board_id = ?`, `thread_id = ?`, FK cascades); a second index would only cost writes.
* **Ordering of the composite `threads` index.** The thread list is `pinned DESC,
  bumped_at DESC`, which a *backward* scan of an all-ASC `(board_id, pinned, bumped_at)`
  index satisfies exactly (`pinned = true` sorts after `false`, so reverse = pinned first).
  Ash appends the primary key as a stable keyset tiebreaker (`ORDER BY pinned DESC,
  bumped_at DESC, id`), which costs one cheap incremental sort over the page.

### EXPLAIN evidence (dev DB, 500 threads / 20 260 posts, then cleaned up)

Thread list (`LIMIT 26`, i.e. 25 + the `more?` probe):

```
Limit (actual rows=26)
  ->  Incremental Sort (Sort Key: pinned DESC, bumped_at DESC, id; Presorted Key: pinned, bumped_at)
        ->  Nested Loop
              ->  Index Scan Backward using threads_board_id_pinned_bumped_at_index on threads t0 (actual rows=27)
                    Index Cond: (board_id = '...'::uuid)
              ->  Materialize -> Index Scan using boards_pkey (hidden filter)
Execution Time: 0.139 ms
```

Posts of a thread:

```
Limit (actual rows=26)
  ->  Nested Loop
        ->  Index Scan using posts_thread_id_id_index on posts p0 (actual rows=26)
              Index Cond: (thread_id = '...'::uuid)
              Filter: (deleted_at IS NULL)
Execution Time: 0.146 ms
```

## 2. Keyset pagination on the public read actions

| Action | Pagination |
| --- | --- |
| `Board :read`, `Board :list_public` | keyset, `default_limit: 25`, `countable false` |
| `Thread :read` | keyset, `default_limit: 25`, `countable false` |
| `Post :in_thread` | keyset, `default_limit: 25`, `countable false` |
| `Post :moderation_queue` | offset, `default_limit: 50`, `countable :by_default` |
| `Board :staff_read`, `Thread :staff_read` | offset, `default_limit: 50`, `countable :by_default` |

Verified in Ash 3.37 (`deps/ash/lib/ash/resource/actions/read.ex`):

* `defaults([:read])` does **not** paginate: an action only paginates when a `pagination`
  block is declared. Hence the explicit blocks above ("the generated `:read` actions support
  pagination" is true only in the sense that `page: [...]` is accepted; nothing is bounded
  without configuration).
* `required?: true` is Ash's default, so a read of a paginated action **always** returns a
  page (`%Ash.Page.Keyset{}` / `%Ash.Page.Offset{}`) unless the caller passes `page: false`
  — impossible here, so an unbounded read cannot happen.
* Relationship loads are exempt (`not relationship?` guard in the pagination code path), so
  `thread.posts` / `board.threads` / `thread.board` still return full lists.
* `Ash.get/3` uses the unpaginated read path, so single-record fetches, policy checks and
  `Ash.get`-based lookups are unaffected.

Consequences for callers: the public list actions now return pages. `Ash.Page` is **not**
`Enumerable`, so `Enum.map(Ash.read!(Board), ...)` fails; use `page.results` (the web
layer's `AccelaImageboardWeb.Content` already consumes `{:ok, %{results: results} = page}`
and passes `page: [limit:, after:]`, which matches this configuration).

Two policy checks had to learn about pages because they read a now-paginated resource
(`Boards.Checks.ThreadOpen`, `Boards.Checks.BoardOpen`): they match either a list or a
page's `results` and deny on anything else (fail closed).

## 3. Seeds (staff provisioning)

`priv/repo/seeds.exs` is idempotent and is the only staff-provisioning path:

* `AccelaImageboard.Seeds.seed_admin/0` — creates the admin with
  `action: :register_with_password, authorize?: false` (self-registration is forbidden by
  policy), then sets `is_staff: true` and `confirmed_at` with `authorize?: false`.
  Password comes from `SEED_ADMIN_PASSWORD`; if unset the admin is **skipped with a loud
  warning** (never a default password). `SEED_ADMIN_EMAIL` defaults to
  `admin@accela.invalid`.
* `seed_boards/0` — `/g/` Technology and `/meta/` Meta, looked up by identity with
  `action: :staff_read` (a hidden board must still be found, otherwise the seed would try to
  duplicate its unique slug).

Verified: first run creates both boards (+ admin when the password is set); second and third
runs report "already exists" for everything and exit 0.

`mix setup` already ends with `run priv/repo/seeds.exs` (mix.exs, not editable from this
change set) — nothing to change there, and it cannot break `mix check` because the `test`
alias runs `ash.setup --quiet` only, and a missing password path exits 0.

## 4. Oban

* `config/config.exs`: `engine: Oban.Engines.Basic`, `repo: AccelaImageboard.Repo`,
  `queues: [default: 10, media: 5]`.
* `config/test.exs`: `testing: :manual, queues: false, plugins: false`.
* `lib/accela_imageboard/application.ex`: `{Oban, Application.fetch_env!(:accela_imageboard, Oban)}`
  directly after the repo it writes through.
* `priv/repo/migrations/20261121004449_add_oban_jobs.exs`: `Oban.Migrations.up()` /
  `down()`. Oban 2.24 ships **no** SQL under `deps/oban/priv`; the schema is Ecto migration
  code in `Oban.Migration`, and a normal migration is the cleanest way to ship it.

Correction to the task's assumption: `testing: :manual` does **not** free you from the
tables. `Oban.start_link/1` calls `Oban.Migration.verify_migrated!/1` whenever
`testing != :disabled` and raises if `oban_jobs` is missing or outdated
(`deps/oban/lib/oban.ex:604-608`, `deps/oban/lib/oban/migration.ex:209-254`). Hence the
migration above runs for dev, test (via the `test` alias' `ash.setup`) and production
alike. `:manual` still disables queues, plugins, the stager and peers, so no job runs
concurrently with a test — `test/accela_imageboard/oban_test.exs` asserts manual mode, the
basic engine, the migrated schema and that a job can be enqueued and asserted with
`Oban.Testing`.

AshOban remains unapplied to every resource, as instructed.

## 5. Cleanup

* `Boards.Changes.SetPosterHash` no longer accepts the legacy `%{"hash" => ...}` map shape:
  the contract is a non-empty binary, matching what the request plug stores
  (`conn.private[:accela_ip_hash] = IpHash.hash(client_ip)` — a hex string; the web layer
  never builds a map). `Boards.Changes.RateLimit` ignores non-binary identities the same
  way instead of keying a bucket on an arbitrary term.
* `Board.has_many :threads` sorted by `inserted_at: :desc`, a column `threads` does not
  have (it would raise on load). Now `sort(pinned: :desc, bumped_at: :desc)` — the
  documented imageboard order, matching the new index.

## 6. Verification

`mix check` is green end to end (exit 0): `format --check-formatted`, `compile
--warnings-as-errors` (Elixir 1.20 type checker), `credo` (431 modules/functions, no
issues), `sobelow`, `doctor` (55 modules, 0 failed, 100% doc coverage) and `mix test
--raise` → **142 tests, 0 failures** (phase 1 had 62; this change set adds
`test/accela_imageboard/pagination_test.exs` with 7 and `test/accela_imageboard/oban_test.exs`
with 4).

Migrations: `20261121004449_add_oban_jobs` and `20261121004530_add_indexes_for_hot_paths`,
both applied to the dev DB with `mix ash.migrate` (and to the test DB by the `test` alias'
`ash.setup`). `Oban.Migration.migrated_version/1` reports version 14.

Pitfall worth knowing: run `mix check` **without** setting `MIX_ENV` in the shell. An
explicit `MIX_ENV=dev` overrides the `preferred_envs: [check: :test]` hint in `mix.exs`, so
the `test` step boots the dev repo (no `Ecto.Adapters.SQL.Sandbox` pool) and fails with
`cannot invoke sandbox operation with pool DBConnection.ConnectionPool`.

## Left for the main agent

1. **`media (post_id)` index ownership**: the migration adds it as raw SQL
   (`media_post_id_hot_path_idx`) because `Boards.Media` is not editable from this change
   set. When that resource declares `custom_indexes do index([:post_id]) end`, drop the raw
   statement so `ash.codegen` stays the single source of truth.
2. **`posts (thread_id, inserted_at)`** requires a `posts.inserted_at` column; a migration
   would backfill existing rows with the migration time. `(thread_id, id)` covers the same
   ordering today.
3. **`oban` is a transitive dependency** (via `ash_oban`), not declared in `mix.exs`. It
   works, but declaring `{:oban, "~> 2.19"}` explicitly in `mix.exs` (not editable here)
   would pin the version the app starts directly.
4. **Web agent**: public list reads return pages now (see §2) and the unaggregated
   `thread.posts`/`board.threads` relationship loads are unchanged. `Content` already
   matches this contract.
5. **Test-database pollution from the parallel work**: `accela_imageboard_test` contains
   committed rows from the web layer's tests (`exp*` boards, `t1..t3` threads,
   `explore-post-*` posts). They leak across sandboxed tests, so domain tests scope their
   assertions to their own rows. Worth a look: something in that suite writes outside the
   sandbox transaction.
