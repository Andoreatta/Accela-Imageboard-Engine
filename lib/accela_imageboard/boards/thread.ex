defmodule AccelaImageboard.Boards.Thread do
  @moduledoc """
  A thread inside a board. Anonymous posters create threads; staff can
  pin/lock/archive them.

  Public reads only expose threads of **visible** boards: the primary read
  filters `board.hidden == false`, and staff reach hidden boards' threads
  through `:staff_read` (audit A2). The `posts` relationship and the
  `post_count`/`first_post_id`/`last_post_id` aggregates all ignore moderated
  (soft-deleted) posts (audit A1).
  """

  use Ash.Resource,
    domain: AccelaImageboard.Boards,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    # The primary read is deliberately filtered (threads of hidden boards are
    # excluded), so every path that resolves a thread inherits the filter.
    # Staff use `:staff_read`.
    primary_read_warning?: false

  postgres do
    table "threads"
    repo AccelaImageboard.Repo
  end

  policies do
    policy action(:read) do
      description(
        "Threads of visible boards are public; hidden boards are excluded by the filter"
      )

      authorize_if(always())
    end

    policy action(:staff_read) do
      description("Staff see threads of hidden boards too")
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end

    policy action(:create) do
      description("Anonymous visitors can create threads on open boards")
      authorize_if(AccelaImageboard.Boards.Checks.BoardOpen)
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end

    policy action([:post_bump, :staff_update, :destroy]) do
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end
  end

  attributes do
    uuid_v7_primary_key(:id)

    attribute(:subject, :string, public?: true)
    attribute(:name, :string, public?: true, description: "Poster-provided nickname")

    # Sticky thread at the top of the board.
    attribute(:pinned, :boolean, default: false, public?: true)
    # Locked threads cannot receive new posts.
    attribute(:locked, :boolean, default: false, public?: true)
    # Archived threads are read-only and stop bumping.
    attribute(:archived, :boolean, default: false, public?: true)

    # Imageboard "bump" ordering.
    attribute :bumped_at, :utc_datetime_usec do
      allow_nil?(false)
      public?(true)
      default(&DateTime.utc_now/0)
    end
  end

  relationships do
    belongs_to :board, AccelaImageboard.Boards.Board do
      allow_nil?(false)
      public?(true)
    end

    has_many :posts, AccelaImageboard.Boards.Post do
      description("Visible posts only — moderated posts are filtered out")
      filter(expr(is_nil(deleted_at)))
    end
  end

  actions do
    read :read do
      primary?(true)
      description("Threads of visible boards — threads of hidden boards excluded")
      filter(expr(board.hidden == false))
    end

    read :staff_read do
      description("Every thread, including threads of hidden boards — staff only")
    end

    create :create do
      primary?(true)

      # Op identity, rate limit and ban check are all keyed off the
      # anonymous poster's IP hash (see `lib/accela_imageboard/boards/changes`).
      change({AccelaImageboard.Boards.Changes.RateLimit, key: :thread_create})
      change(AccelaImageboard.Boards.Changes.BannedPoster)

      accept([:subject, :name, :board_id])
    end

    update :post_bump do
      description("Bump a thread when a new post is added")
      change(set_attribute(:bumped_at, &DateTime.utc_now/0))
    end

    update :staff_update do
      description("Pin/lock/archive — staff only")
      require_atomic?(false)
      accept([:pinned, :locked, :archived, :subject])

      change(
        {AccelaImageboard.Moderation.Changes.LogAction,
         action: "thread.staff_update", target_type: "Thread"}
      )
    end

    destroy :destroy do
      primary?(true)
    end
  end

  aggregates do
    # Moderated posts are not content: they must not be counted or bump a
    # thread to the top (audit A1).
    #
    # `posts` has no timestamp column in this schema (adding one needs a
    # migration), so ordering uses the uuid_v7 primary key, which is time
    # ordered: the first/last id are the first/last post.
    first :first_post_id, :posts, :id do
      sort(id: :asc)
      filter(expr(is_nil(deleted_at)))
    end

    first :last_post_id, :posts, :id do
      sort(id: :desc)
      filter(expr(is_nil(deleted_at)))
    end

    count :post_count, :posts do
      filter(expr(is_nil(deleted_at)))
    end
  end
end
