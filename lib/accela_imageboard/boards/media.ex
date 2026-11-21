defmodule AccelaImageboard.Boards.Media do
  @moduledoc """
  An uploaded image attached to a post.

  Upload files never go through `Plug.Upload` straight to disk: the web layer
  validates magic bytes, size and type before handing a `storage_key` over
  (see `AccelaImageboard.Media.Storage`). The file is served through a
  controller - never statically - so that correct headers (nosniff,
  content-type allow-list, cache) are always applied.

  ## Attaching

  `:attach` is deliberately **not** a public create action. It is authorized by
  `AccelaImageboard.Media.Checks.PostFlowAttach`, which requires the server-side
  `media_upload: %{post_flow: true}` marker *and* a visible post inside an open
  thread, so media can only appear as part of creating a reply. Staff keep their
  own branch. A direct call without the marker fails closed.

  The `:sha256` identity makes content-addressed deduplication possible: uploading
  the same bytes twice updates the existing row (its `post_id` moves to the newest
  post) instead of storing a second copy. Deduplicating *across* posts would need a
  join table; see the operations notes.
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
      description("Images are public content of public posts")
      authorize_if(always())
    end

    policy action(:attach) do
      description("Attaching media happens only inside the anonymous post flow")

      authorize_if(AccelaImageboard.Media.Checks.PostFlowAttach)
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end

    policy action(:detach) do
      description("Removing an attachment is staff-only")
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
