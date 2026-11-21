defmodule AccelaImageboard.Boards.Board do
  @moduledoc """
  A board (category) that groups threads — e.g. `/g/`, `/a/`.

  Fully public to read; creation/edition is staff-only.
  """

  use Ash.Resource,
    domain: AccelaImageboard.Boards,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "boards"
    repo AccelaImageboard.Repo
  end

  policies do
    # Boards are publicly listable/readable (hidden boards excluded by
    # the :list_public filter; a staff reader can read any board by id).
    policy action([:list_public]) do
      authorize_if(always())
    end

    policy action_type(:read) do
      authorize_if(always())
    end

    # Everything else is staff-only.
    policy action_type([:create, :update, :destroy]) do
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end
  end

  attributes do
    uuid_v7_primary_key(:id)

    attribute(:slug, :string, allow_nil?: false, public?: true)
    attribute(:name, :string, allow_nil?: false, public?: true)
    attribute(:description, :string, public?: true)
    attribute(:rules, :string, public?: true)

    # When true, only staff can create threads (used for announcement boards).
    attribute(:staff_only_threads, :boolean, default: false, public?: true)
    # Soft-hide a whole board without destroying data.
    attribute(:hidden, :boolean, default: false, public?: true)
  end

  relationships do
    has_many :threads, AccelaImageboard.Boards.Thread do
      sort(inserted_at: :desc)
    end
  end

  actions do
    defaults([:read])

    read :list_public do
      description("Boards visible to anonymous visitors")
      filter(expr(hidden == false))
      prepare(build(sort: [slug: :asc]))
    end

    create :create do
      primary?(true)
      accept([:slug, :name, :description, :rules, :staff_only_threads])
    end

    update :update do
      primary?(true)
      accept([:slug, :name, :description, :rules, :staff_only_threads, :hidden])
    end

    destroy :destroy do
      primary?(true)
    end
  end

  identities do
    identity(:slug, [:slug])
  end
end
