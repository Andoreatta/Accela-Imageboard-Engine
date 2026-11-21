defmodule AccelaImageboard.Repo.Migrations.AddIndexesForHotPaths do
  @moduledoc """
  Indexes for the read paths the public pages and the moderation flow hit.

  Generated with `mix ash.codegen add_indexes_for_hot_paths` from the
  `custom_indexes` blocks of `Boards.Thread`, `Boards.Post`, `Moderation.Ban`
  and `Moderation.Report` — those resources are the source of truth; this file
  only carries the SQL.

  ## The ordering decisions behind the columns

  * `threads (board_id, pinned, bumped_at)` — the thread list of a board is
    `WHERE board_id = ? ORDER BY pinned DESC, bumped_at DESC` (pinned threads
    first, then most recently bumped). A btree with all three columns ASC is
    read **backwards** by Postgres for that query, so one index scan covers the
    filter, the ordering and the `LIMIT`. The `board_id` prefix also serves the
    board foreign key, "how many threads has this board" and `Thread.staff_read`.
  * `posts (thread_id, id)` — a thread's posts are
    `WHERE thread_id = ? ORDER BY id` (see `Post.read :in_thread`). `posts` has
    **no `inserted_at` column** in this schema and adding one would backfill
    every existing row with the migration timestamp, so the uuid_v7 primary key
    (time ordered by construction) is the ordering column. The `thread_id`
    prefix also serves the foreign key cascade when a thread is deleted.
  * `bans (poster_hash, expires_at)` — every ban check is
    `poster_hash = ? AND (expires_at IS NULL OR expires_at > now())`; the
    `poster_hash` prefix alone covers plain lookups, so no separate index.
  * `reports (post_id)` and `reports (state)` — "reports for this post" (post
    moderation view) and the staff triage queue (by state) are different
    queries, so they get different indexes.
  * `media (post_id)` — added as plain SQL on purpose: `Boards.Media` is owned
    by another agent in this change set. When that resource declares
    `custom_indexes do index([:post_id]) end`, delete the statement below so
    `ash.codegen` stays the single source of truth (the distinct index name
    keeps both versions from colliding in the meantime).
  """

  use Ecto.Migration

  def up do
    create index(:bans, [:poster_hash, :expires_at])

    create index(:posts, [:thread_id, :id])

    create index(:reports, [:post_id])

    create index(:reports, [:state])

    create index(:threads, [:board_id, :pinned, :bumped_at])

    # See the moduledoc: interim index for `media.post_id` (the resource is not
    # editable from this change set). Deliberately a distinct name so a future
    # Ash-managed `media_post_id_index` cannot collide with it.
    create_if_not_exists index(:media, [:post_id], name: :media_post_id_hot_path_idx)
  end

  def down do
    drop_if_exists index(:media, [:post_id], name: :media_post_id_hot_path_idx)

    drop_if_exists index(:threads, [:board_id, :pinned, :bumped_at])

    drop_if_exists index(:reports, [:state])

    drop_if_exists index(:reports, [:post_id])

    drop_if_exists index(:posts, [:thread_id, :id])

    drop_if_exists index(:bans, [:poster_hash, :expires_at])
  end
end
