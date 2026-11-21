defmodule AccelaImageboard.Boards.Board do
  @moduledoc """
  A board (category) that groups threads — e.g. `/g/`, `/a/`.

  Publicly readable; creation/edition is staff-only. A board can be
  soft-hidden (`hidden`), and the primary read filters hidden boards out, so
  hiding a board actually hides it and its threads from anonymous visitors.
  Staff reach hidden boards through `:staff_read` (audit A2) — note that
  `board.threads` goes through the Thread primary read, so a staff console
  lists the threads of a hidden board with
  `Thread |> Ash.Query.filter(board_id == ^board.id) |> Ash.read(action: :staff_read, actor: staff)`.
  """

  use Ash.Resource,
    domain: AccelaImageboard.Boards,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    # The primary read is deliberately filtered (hidden boards excluded), so
    # every path that resolves a board inherits the filter. Staff use
    # `:staff_read`.
    primary_read_warning?: false

  postgres do
    table "boards"
    repo AccelaImageboard.Repo
  end

  policies do
    # Public reads: hidden boards are excluded by the action filters.
    policy action([:read, :list_public]) do
      authorize_if(always())
    end

    # Staff-only read that includes hidden boards.
    policy action(:staff_read) do
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
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
    read :read do
      primary?(true)
      description("Boards visible to anonymous visitors — hidden boards excluded")
      filter(expr(hidden == false))
    end

    read :list_public do
      description("Boards visible to anonymous visitors")
      filter(expr(hidden == false))
      prepare(build(sort: [slug: :asc]))
    end

    read :staff_read do
      description("Every board, including hidden ones — staff only")
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
