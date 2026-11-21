defmodule AccelaImageboard.Boards.Changes.SetPosterIdentity do
  @moduledoc """
  Stores the poster's *network* and *token* identifiers next to the exact IP
  hash set by `AccelaImageboard.Boards.Changes.SetPosterHash`.

  The exact hash answers "which address posted this"; it is also what rate
  limits count. It is not enough to enforce a ban, because rotating the address
  (VPN exit rotation, mobile roaming, Tor, CGNAT) produces a new hash and the
  ban is silently evaded. Each piece of content therefore records up to two
  extra keyed HMACs, so a ban can target more than one address and staff can
  ban retroactively:

  | identifier | comes from | ban scope that matches it |
  | --- | --- | --- |
  | `poster_hash` | `SetPosterHash` (v1) | `:exact` |
  | `net_hash` + `net_scope` | `AccelaImageboard.Security.IpHash.net/1` | `:ipv4_24` / `:ipv6_64` |
  | `token_hash` | `AccelaImageboard.Security.TokenHash.hash/1` | `:token` |

  ## Contract (server-side only, never from parameters)

      Ash.create(..., context: %{anonymous: %{
        ip_hash: "...",                                   # v1, unchanged
        net_scope: :ipv4_24 | :ipv6_64, net_hash: "...",  # v2, optional
        token_hash: "..."                                 # v2, optional
      }})

  A v1 caller (only `ip_hash`) keeps working: the new columns stay `nil`. None of
  these identifiers may ever be claimed by a client — a poster who could present
  a network or token identity would simply pick a clean one.

  ## Everything fails closed

    * `net_scope` and `net_hash` must be **both** present or **both** absent; a
      half pair is a contract bug, not a reason to store a partial identity;
    * `net_scope` must be `:ipv4_24` or `:ipv6_64`, and both hashes must be
      non-empty binaries;
    * `token_hash` follows the same rule when present.

  Anything else adds a changeset error, so content is never stored with a
  partially recorded identity (and `SetPosterHash` independently refuses to
  attribute content at all without the exact hash).
  """

  use Ash.Resource.Change

  @scopes [:ipv4_24, :ipv6_64]
  @malformed "malformed anonymous identity — refusing to attribute this post"

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, &put_identity/1)
  end

  defp put_identity(changeset) do
    anonymous = changeset.context[:anonymous] || %{}

    case identity(anonymous) do
      {:ok, net_scope, net_hash, token_hash} ->
        changeset
        |> force(:net_scope, net_scope)
        |> force(:net_hash, net_hash)
        |> force(:token_hash, token_hash)

      {:error, field} ->
        Ash.Changeset.add_error(changeset, field: field, message: @malformed)
    end
  end

  defp identity(anonymous) do
    with {:ok, net_scope, net_hash} <- net_pair(anonymous),
         {:ok, token_hash} <- token_hash(anonymous) do
      {:ok, net_scope, net_hash, token_hash}
    end
  end

  # Both or neither: a scope without a hash (or the reverse) cannot be stored.
  defp net_pair(anonymous) do
    case {Map.get(anonymous, :net_scope), Map.get(anonymous, :net_hash)} do
      {nil, nil} ->
        {:ok, nil, nil}

      {scope, hash} when scope in @scopes and is_binary(hash) and byte_size(hash) > 0 ->
        {:ok, scope, hash}

      _mismatched_or_malformed ->
        {:error, :net_hash}
    end
  end

  defp token_hash(anonymous) do
    case Map.get(anonymous, :token_hash) do
      nil ->
        {:ok, nil}

      hash when is_binary(hash) and byte_size(hash) > 0 ->
        {:ok, hash}

      _malformed ->
        {:error, :token_hash}
    end
  end

  defp force(changeset, _field, nil), do: changeset

  defp force(changeset, field, value) do
    Ash.Changeset.force_change_attribute(changeset, field, value)
  end
end
