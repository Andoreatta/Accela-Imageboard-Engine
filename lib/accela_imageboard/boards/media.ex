defmodule AccelaImageboard.Boards.Media do
  @moduledoc """
  An uploaded image attached to a post.

  Upload files never go through `Plug.Upload` straight to disk: the web layer
  validates magic bytes, size and type before handing a `storage_key` over
  (see `AccelaImageboard.Media.Storage`). The file is served through a
  controller — never statically — so that correct headers (nosniff,
  content-type allow-list, cache) are always applied.
  """

  use Ash.Resource,
    domain: AccelaImageboard.Boards,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "media"
    repo AccelaImageboard.Repo
  end

  policies do
    policy action_type(:read) do
      authorize_if(always())
    end

    policy action([:attach, :detach]) do
      # The web layer attaches media as part of the (authorized) post flow;
      # no direct anonymous access to this resource.
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end
  end

  attributes do
    uuid_v7_primary_key(:id)

    attribute :storage_key, :string do
      allow_nil?(false)
      public?(true)
      description("Opaque storage key — not a user path")
    end

    attribute(:original_filename, :string, public?: true)
    # Only image/* types are accepted; enforced at upload by magic-byte checks.
    attribute(:content_type, :string, allow_nil?: false, public?: true)
    attribute(:byte_size, :integer, allow_nil?: false, public?: true)

    # Deduplication & integrity.
    attribute(:sha256, :string, allow_nil?: false, public?: false)
  end

  relationships do
    belongs_to :post, AccelaImageboard.Boards.Post do
      allow_nil?(false)
      public?(true)
    end
  end

  actions do
    defaults([:read])

    create :attach do
      primary?(true)
      upsert?(true)
      upsert_identity(:sha256)
      accept([:storage_key, :original_filename, :content_type, :byte_size, :sha256, :post_id])
    end

    destroy :detach do
      primary?(true)
    end
  end

  identities do
    identity(:storage_key, [:storage_key])
    identity(:sha256, [:sha256])
  end
end
