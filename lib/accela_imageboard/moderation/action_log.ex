defmodule AccelaImageboard.Moderation.ActionLog do
  @moduledoc """
  Immutable record of staff moderation actions (who did what, to what).

  Complements `ash_paper_trail` data-versioning (which answers "what changed
  in a row") with an actor-facing audit trail ("which staff member did it").
  Rows are insert-only: no update/destroy actions exist.

  `staff_id` is never public input: it is derived from the action's actor by
  `AccelaImageboard.Moderation.Changes.StaffActor`, so attribution cannot be
  forged (audit F-12). Staff actions write their own entries through
  `AccelaImageboard.Moderation.Changes.LogAction` (audit F-13).
  """

  use Ash.Resource,
    domain: AccelaImageboard.Moderation,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "moderation_action_logs"
    repo AccelaImageboard.Repo
  end

  # Append-only resource: no update/destroy actions, staff-only reads.
  policies do
    policy always() do
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end
  end

  attributes do
    uuid_v7_primary_key(:id)

    attribute(:action, :string, allow_nil?: false)
    attribute(:target_type, :string, allow_nil?: false)
    attribute(:target_id, :string, allow_nil?: false)
    attribute(:detail, :map)

    create_timestamp(:inserted_at)
  end

  relationships do
    belongs_to :staff, AccelaImageboard.Accounts.User do
      allow_nil?(false)
    end
  end

  actions do
    defaults([])

    # Primary read stays bare: it is used by the framework for loading
    # relationships and policy checks and must not have preparations.
    read :read do
      primary?(true)
    end

    read :list do
      description("Staff console list of actions, newest first")
      prepare(build(sort: [inserted_at: :desc]))
    end

    create :log do
      primary?(true)
      # `staff_id` is deliberately absent: it is force-set from the actor.
      accept([:action, :target_type, :target_id, :detail])
      change(AccelaImageboard.Moderation.Changes.StaffActor)
    end
  end
end
