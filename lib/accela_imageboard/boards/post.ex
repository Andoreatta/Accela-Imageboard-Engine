defmodule AccelaImageboard.Boards.Post do
  @moduledoc """
  A single reply (or OP) inside a thread.

  Created mostly by anonymous posters; `poster_hash` stores a keyed HMAC of
  the poster's IP (see `AccelaImageboard.Security.IpHash`) — never the raw IP.
  """

  use Ash.Resource,
    domain: AccelaImageboard.Boards,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "posts"
    repo AccelaImageboard.Repo

    references do
      reference :thread, on_delete: :delete
    end
  end

  policies do
    policy action_type(:read) do
      authorize_if(always())
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

    # Staff moderation marks (content stays unless destroyed).
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
    defaults([:read])

    read :in_thread do
      description("Posts of a thread, visible to everyone")
      filter(expr(is_nil(deleted_at)))
      prepare(build(sort: [inserted_at: :asc]))
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
      accept([])
      change(set_attribute(:deleted_at, &DateTime.utc_now/0))
    end

    destroy :destroy do
      primary?(true)
    end
  end
end
