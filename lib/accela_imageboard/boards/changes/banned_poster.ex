defmodule AccelaImageboard.Boards.Changes.BannedPoster do
  @moduledoc """
  Blocks content creation from a poster whose **anonymous identity set** matches
  any active ban in the `AccelaImageboard.Moderation` domain.

  A ban has a `:scope`, and this check honours all of them against the
  identifiers the server put in `changeset.context[:anonymous]` (see
  `AccelaImageboard.Boards.Changes.SetPosterIdentity`):

  | ban scope | blocks when |
  | --- | --- |
  | `:exact` | `poster_hash` equals the context's `ip_hash` |
  | `:ipv4_24` / `:ipv6_64` | `poster_hash` equals the context's `net_hash` and the scope matches `net_scope` |
  | `:token` | `poster_hash` equals the context's `token_hash` |

  One query covers all three (a single `OR` of the identifiers that are actually
  present), so a poster rotating their address inside a provider block, or
  carrying a previously banned cookie, is still blocked.

  ## Evasion signal

  When the block is *only* due to the network or token identifier — i.e. the
  exact hash is not itself banned — that is evidence of evasion, and a
  `Logger.warning` records it. Hashes are never logged in full: at most a
  12-character prefix, which is enough to correlate two log lines and useless
  for re-identifying a poster.

  ## Machine check

  This is a server-side enforcement check, not a user read: the identity comes
  exclusively from the changeset context (never from user input), and the read
  runs with `authorize?: false` because ban records stay staff-only through
  every other path (all `Ban` policies require a staff actor). A read error is
  treated as "banned" — enforcement is fail-closed. A context without any
  identifier at all passes through here; `SetPosterHash` refuses to attribute
  the content in that case, so nothing is stored unattributed.
  """

  use Ash.Resource.Change

  require Logger

  alias AccelaImageboard.Moderation.Ban

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, &check_bans/1)
  end

  defp check_bans(changeset) do
    identity = identity(changeset)

    case identity |> clauses() |> active_bans() do
      {:ok, []} ->
        changeset

      {:ok, bans} ->
        refuse(changeset, identity, bans)

      # Fail closed: if we cannot check, we do not allow the post.
      {:error, _reason} ->
        banned(changeset)
    end
  end

  defp identity(changeset) do
    anonymous = changeset.context[:anonymous] || %{}

    %{
      ip_hash: Map.get(anonymous, :ip_hash),
      net_scope: Map.get(anonymous, :net_scope),
      net_hash: Map.get(anonymous, :net_hash),
      token_hash: Map.get(anonymous, :token_hash)
    }
  end

  # Only the identifiers we actually have can match; a missing one contributes
  # nothing to the OR (and no `nil` ever reaches SQL).
  defp clauses(identity) do
    [
      {identity.ip_hash, :exact},
      {identity.net_hash, identity.net_scope},
      {identity.token_hash, :token}
    ]
    |> Enum.reject(fn {hash, scope} -> is_nil(hash) or is_nil(scope) end)
  end

  defp active_bans([]), do: {:ok, []}

  defp active_bans([{_hash, _scope} | _rest] = clauses) do
    import Ash.Expr

    now = DateTime.utc_now()

    Ban
    |> Ash.Query.do_filter(
      or:
        Enum.map(clauses, fn {hash, scope} ->
          %{scope: scope, poster_hash: hash}
        end)
    )
    |> Ash.Query.filter(expr(is_nil(expires_at) or expires_at > ^now))
    |> Ash.read(authorize?: false)
  end

  defp refuse(changeset, identity, bans) do
    scopes = bans |> Enum.map(& &1.scope) |> Enum.uniq()

    unless :exact in scopes do
      Logger.warning(
        "ban evasion signal: posting blocked by #{inspect(scopes)} scope only " <>
          "(net=#{prefix(identity.net_hash)} token=#{prefix(identity.token_hash)})"
      )
    end

    banned(changeset)
  end

  defp banned(changeset) do
    Ash.Changeset.add_error(changeset, field: :banned, message: "posting is not allowed")
  end

  # Never log a full hash: a prefix is enough to correlate log lines and useless
  # for re-identifying the poster.
  defp prefix(nil), do: "none"
  defp prefix(hash) when is_binary(hash), do: String.slice(hash, 0, 12)
end
