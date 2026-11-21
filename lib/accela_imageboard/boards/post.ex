defmodule AccelaImageboard.Boards.Post do
  @moduledoc """
  A single reply (or OP) inside a thread.

  Created mostly by anonymous posters; `poster_hash` stores a keyed HMAC of
  the poster's IP (see `AccelaImageboard.Security.IpHash`) — never the raw IP.

  Moderation is a soft delete (`deleted_at`). Every public read path — the
  primary read, the `Thread.posts` relationship and the thread aggregates —
  filters `is_nil(deleted_at)`, so a moderated post disappears for everyone
  except staff, who reach it through the `:moderation_queue` action.
  """

  use Ash.Resource,
    domain: AccelaImageboard.Boards,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    # The primary read is deliberately filtered (moderated posts excluded), so
    # every path that resolves a post — including relationship loads and
    # policy checks — inherits the filter. Staff use `:moderation_queue`.
    primary_read_warning?: false

  postgres do
    table "posts"
    repo AccelaImageboard.Repo

    references do
      reference :thread, on_delete: :delete
    end
  end

  policies do
    policy action([:read, :in_thread]) do
      description("Public post reads — moderated content is filtered out by the actions")
      authorize_if(always())
    end

    policy action(:moderation_queue) do
      description("Moderation views include soft-deleted posts, so they are staff-only")
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end

    policy action(:create) do
      description("Anonymous posting is allowed on open threads")
      authorize_if(AccelaImageboard.Boards.Checks.ThreadOpen)
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end

    policy action([:moderate, :destroy]) do
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end
  end

  attributes do
    uuid_v7_primary_key(:id)

    attribute(:body, :string, allow_nil?: false, public?: true, constraints: [max_length: 10_000])

    attribute(:name, :string, public?: true, description: "Poster-provided nickname")

    attribute :poster_hash, :string do
      allow_nil?(false)
      public?(false)
      description("Keyed HMAC of the poster IP — never a raw IP")
    end

    attribute(:is_op, :boolean, default: false, public?: false)

    # Staff moderation mark (content stays unless destroyed).
    attribute(:deleted_at, :utc_datetime_usec, public?: false)
  end

  relationships do
    belongs_to :thread, AccelaImageboard.Boards.Thread do
      allow_nil?(false)
      public?(true)
    end

    has_many :media, AccelaImageboard.Boards.Media
  end

  actions do
    read :read do
      primary?(true)
      description("Posts visible to everyone — moderated (soft-deleted) posts excluded")
      filter(expr(is_nil(deleted_at)))
    end

    read :in_thread do
      description("Posts of a thread, visible to everyone")
      filter(expr(is_nil(deleted_at)))
      # Posts carry no timestamp in this schema; ids are uuid_v7, i.e. time
      # ordered, so they are the insertion order.
      prepare(build(sort: [id: :asc]))
    end

    read :moderation_queue do
      description("Every post including moderated ones, newest first — staff only")
      prepare(build(sort: [id: :desc]))
    end

    create :create do
      primary?(true)

      change({AccelaImageboard.Boards.Changes.RateLimit, key: :post_create})
      change(AccelaImageboard.Boards.Changes.BannedPoster)
      change(AccelaImageboard.Boards.Changes.SetPosterHash)

      accept([:body, :name, :thread_id])
    end

    # Staff soft-deletes: content disappears but rows remain for audit.
    update :moderate do
      description("Soft-delete a post as staff")
      require_atomic?(false)
      accept([])
      change(set_attribute(:deleted_at, &DateTime.utc_now/0))

      change(
        {AccelaImageboard.Moderation.Changes.LogAction,
         action: "post.moderate", target_type: "Post"}
      )
    end

    destroy :destroy do
      primary?(true)
    end
  end
end
