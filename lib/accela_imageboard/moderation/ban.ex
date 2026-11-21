defmodule AccelaImageboard.Moderation.Ban do
  @moduledoc """
  An active or historical ban of an anonymous poster (keyed by IP hash) or
  a staff ban of an account.

  The poster's raw IP is never stored — only the keyed HMAC
  (`AccelaImageboard.Security.IpHash`).
  """

  use Ash.Resource,
    domain: AccelaImageboard.Moderation,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "bans"
    repo AccelaImageboard.Repo
  end

  policies do
    # Enforcement is called by the posting flow with authorize?: false
    # through a dedicated API; end users never read bans directly.
    policy always() do
      description("All ban data is staff-only")
      authorize_if(AccelaImageboard.PolicyChecks.Staff)
    end
  end

  attributes do
    uuid_v7_primary_key(:id)

    attribute :poster_hash, :string do
      allow_nil?(false)
      description("Keyed HMAC of the banned poster's IP")
    end

    attribute(:reason, :string, allow_nil?: false)
    attribute(:expires_at, :utc_datetime_usec, description: "nil = permanent")

    create_timestamp(:inserted_at)
    update_timestamp(:updated_at)
  end

  relationships do
    # Staff member who issued the ban.
    belongs_to :issued_by, AccelaImageboard.Accounts.User do
      allow_nil?(false)
    end
  end

  actions do
    defaults([:read])

    read :active do
      description("Active (non-expired) bans — used by the posting flow")
      filter(expr(is_nil(expires_at) or expires_at > ^DateTime.utc_now()))
    end

    read :check do
      description("Is a given poster_hash currently banned?")
      get?(true)
      filter(expr(poster_hash == ^arg(:poster_hash)))
      argument(:poster_hash, :string, allow_nil?: false)
      filter(expr(is_nil(expires_at) or expires_at > ^DateTime.utc_now()))
    end

    create :ban do
      primary?(true)
      accept([:poster_hash, :reason, :expires_at, :issued_by_id])
    end

    destroy :lift do
      primary?(true)
    end
  end
end
