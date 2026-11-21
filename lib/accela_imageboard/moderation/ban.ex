defmodule AccelaImageboard.Moderation.Ban do
  @moduledoc """
  An active or historical ban of an anonymous poster (keyed by IP hash) or
  a staff ban of an account.

  The poster's raw IP is never stored — only the keyed HMAC
  (`AccelaImageboard.Security.IpHash`).

  ## What `poster_hash` identifies: `scope`

  A ban targets one identifier, and `scope` says which kind it is:

  | scope | `poster_hash` holds | survives |
  | --- | --- | --- |
  | `:exact` (default) | `IpHash.hash/1` of one address | nothing — change address and the ban is dodged |
  | `:ipv4_24` | `IpHash.net/1` hash of the /24 | address churn inside the /24 (VPN rotation, CGNAT) |
  | `:ipv6_64` | `IpHash.net/1` hash of the /64 | host-suffix churn / privacy addresses |
  | `:token` | `TokenHash.hash/1` of a session token | address changes, as long as the cookie is kept |

  The network and token hashes are recorded on every post that had them (see
  `AccelaImageboard.Boards.Changes.SetPosterIdentity`), which is what makes a
  retroactive, evasion-resistant ban possible: staff read the identifiers off
  the content instead of guessing an address. Existing rows are `:exact`, so the
  column is purely additive.

  `:check` returns every active ban matching a poster hash (possibly none).
  Callers must treat a *read error* as "banned": enforcement is fail-closed.
  """

  use Ash.Resource,
    domain: AccelaImageboard.Moderation,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "bans"
    repo AccelaImageboard.Repo

    custom_indexes do
      # Every ban check is "is this poster_hash banned and not expired?" (the
      # `:check` action and the posting flow's fail-closed lookup). The leading
      # column also covers lookups by poster_hash alone.
      index([:poster_hash, :expires_at])
    end
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

      description(
        "The banned identifier — meaning depends on scope: an exact IP hash, " <>
          "a network prefix hash, or a token hash (never a raw IP or token)"
      )
    end

    attribute :scope, :atom do
      allow_nil?(false)
      default(:exact)
      constraints(one_of: [:exact, :ipv4_24, :ipv6_64, :token])
      description("Which identifier poster_hash holds — see the moduledoc")
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
    read :read do
      primary?(true)
    end

    read :active do
      description("Active (non-expired) bans — used by the posting flow")
      filter(expr(is_nil(expires_at) or expires_at > ^DateTime.utc_now()))
    end

    # A plain filtered read, not a `get?`: `poster_hash` is not unique, so a
    # poster with two active bans would make a single-result read blow up
    # (audit F-15). Callers treat "no rows" as "not banned".
    read :check do
      description("Active bans for a given poster_hash — empty when the poster is not banned")
      filter(expr(poster_hash == ^arg(:poster_hash)))
      argument(:poster_hash, :string, allow_nil?: false)
      filter(expr(is_nil(expires_at) or expires_at > ^DateTime.utc_now()))
    end

    create :ban do
      primary?(true)
      accept([:poster_hash, :scope, :reason, :expires_at, :issued_by_id])

      change(
        {AccelaImageboard.Moderation.Changes.LogAction, action: "ban.ban", target_type: "Ban"}
      )
    end

    destroy :lift do
      primary?(true)
      # Auditing the lift runs after the delete, so the action is not atomic.
      require_atomic?(false)

      change(
        {AccelaImageboard.Moderation.Changes.LogAction, action: "ban.lift", target_type: "Ban"}
      )
    end
  end
end
