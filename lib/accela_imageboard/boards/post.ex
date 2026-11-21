defmodule AccelaImageboard.Boards.Post do
  @moduledoc """
  A single reply (or OP) inside a thread.

  Created mostly by anonymous posters; `poster_hash` stores a keyed HMAC of
  the poster's IP (see `AccelaImageboard.Security.IpHash`) — never the raw IP.

  Moderation is a soft delete (`deleted_at`). Every public read path — the
  primary read, the `Thread.posts` relationship and the thread aggregates —
  filters `is_nil(deleted_at)`, so a moderated post disappears for everyone
  except staff, who reach it through the `:moderation_queue` action.

  ## Pagination

  `:in_thread` uses keyset pagination (`default_limit: 25`, not countable) and
  `:moderation_queue` offset pagination (`default_limit: 50`, countable by
  default). Both are `required?` (Ash's default), so a read of these actions
  always returns a page (`%Ash.Page.Keyset{}` / `%Ash.Page.Offset{}`) and can
  never stream a thread's entire history. The primary `:read` — used by
  `Ash.get/3`, relationship loads and policy checks — is deliberately *not*
  paginated.
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

    custom_indexes do
      # The reads that matter: "posts of a thread, oldest first"
      # (`WHERE thread_id = ? ORDER BY id`, see `:in_thread`) and the
      # foreign-key cascade when a thread is deleted. The leading `thread_id`
      # column also serves lookups/counts that filter on the thread alone, so
      # no separate single-column index is needed.
      #
      # `posts` has no `inserted_at` column (adding one needs a migration and
      # would backfill every row with the migration time), and ids are uuid_v7
      # — i.e. time ordered — so `id` is the insertion-order key to sort on.
      index([:thread_id, :id])
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

      # A thread can hold thousands of posts: keyset (not offset) pagination,
      # so a deep page costs the same as the first one. With Ash's defaults
      # (`required?: true`) a plain read of this action is paginated too, so an
      # unbounded read is impossible; `countable false` avoids a COUNT per page.
      pagination do
        keyset?(true)
        default_limit(25)
        countable(false)
      end
    end

    read :moderation_queue do
      description("Every post including moderated ones, newest first — staff only")
      prepare(build(sort: [id: :desc]))

      # Staff console: offset pagination with a total count (small, triaged
      # working set — deep pages are not a performance concern here).
      pagination do
        offset?(true)
        default_limit(50)
        countable(:by_default)
      end
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
