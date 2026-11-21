defmodule AccelaImageboard.Moderation.Report do
  @moduledoc """
  A user report against a post, with a staff triage workflow.

  Anonymous visitors create reports; only staff can advance the state.
  The state machine is enforced with `ash_state_machine`.
  """

  use Ash.Resource,
    domain: AccelaImageboard.Moderation,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshStateMachine]

  postgres do
    table "reports"
    repo AccelaImageboard.Repo
  end

  policies do
    policy action_type(:create) do
      authorize_if(always())
    end

    policy action_type([:read, :update]) do
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end
  end

  state_machine do
    initial_states([:open])
    default_initial_state(:open)

    transitions do
      transition(:accept, from: [:open], to: :accepted)
      transition(:reject, from: [:open, :accepted], to: :rejected)
      transition(:resolve, from: [:accepted, :open], to: :resolved)
    end
  end

  attributes do
    uuid_v7_primary_key(:id)

    attribute(:post_id, :uuid_v7, allow_nil?: false)
    attribute(:reason, :string, allow_nil?: false, constraints: [max_length: 2_000])
    attribute(:reporter_hash, :string, allow_nil?: false)

    create_timestamp(:inserted_at)
    update_timestamp(:updated_at)
  end

  actions do
    defaults([:read])

    create :create do
      primary?(true)
      change({AccelaImageboard.Boards.Changes.SetPosterHash, attr: :reporter_hash})
      change({AccelaImageboard.Boards.Changes.RateLimit, key: :report_create})
      accept([:post_id, :reason])
    end

    update(:accept)
    update(:reject)
    update(:resolve)
  end
end
