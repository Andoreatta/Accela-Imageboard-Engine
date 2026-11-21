defmodule AccelaImageboard.Boards.Thread do
  @moduledoc """
  A thread inside a board. Anonymous posters create threads; staff can
  pin/lock/archive them.
  """

  use Ash.Resource,
    domain: AccelaImageboard.Boards,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "threads"
    repo AccelaImageboard.Repo
  end

  policies do
    policy action_type(:read) do
      authorize_if(always())
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

    has_many :posts, AccelaImageboard.Boards.Post
  end

  actions do
    defaults([:read])

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
      accept([:pinned, :locked, :archived, :subject])
    end

    destroy :destroy do
      primary?(true)
    end
  end

  aggregates do
    first(:first_post_at, :posts, :inserted_at)
    first(:last_post_at, :posts, :inserted_at)
    count(:post_count, :posts)
  end
end
