defmodule AccelaImageboard.Moderation.Report do
  @moduledoc """
  A user report against a post, with a staff triage workflow.

  Anonymous visitors create reports; only staff can advance the state.
  The state machine is enforced with `ash_state_machine`.

  `post_id` comes from an untrusted visitor, so `Report.create` fails closed
  unless it resolves to an existing, live post (audit F-17), and every staff
  transition appends an audit-log entry (audit F-13).
  """

  use Ash.Resource,
    domain: AccelaImageboard.Moderation,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshStateMachine]

  postgres do
    table "reports"
    repo AccelaImageboard.Repo

    custom_indexes do
      # "all reports for this post" (post moderation view) …
      index([:post_id])
      # … and the staff triage queue, which lists by state.
      index([:state])
    end
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
      change(AccelaImageboard.Moderation.Changes.ExistingPost)
      accept([:post_id, :reason])
    end

    update :accept do
      require_atomic?(false)
      change(transition_state(:accepted))

      change(
        {AccelaImageboard.Moderation.Changes.LogAction,
         action: "report.accept", target_type: "Report"}
      )
    end

    update :reject do
      require_atomic?(false)
      change(transition_state(:rejected))

      change(
        {AccelaImageboard.Moderation.Changes.LogAction,
         action: "report.reject", target_type: "Report"}
      )
    end

    update :resolve do
      require_atomic?(false)
      change(transition_state(:resolved))

      change(
        {AccelaImageboard.Moderation.Changes.LogAction,
         action: "report.resolve", target_type: "Report"}
      )
    end
  end
end
