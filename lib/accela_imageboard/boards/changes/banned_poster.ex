defmodule AccelaImageboard.Boards.Changes.BannedPoster do
  @moduledoc """
  Blocks content creation from posters with an active ban in the
  `AccelaImageboard.Moderation` domain.

  This is a server-side enforcement check: the anonymous poster's identity
  comes exclusively from `changeset.context[:anonymous][:ip_hash]`, never
  from user input, so it cannot be spoofed.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      changeset
      |> anonymous_hash()
      |> check_ban(changeset)
    end)
  end

  defp anonymous_hash(changeset), do: get_in(changeset.context, [:anonymous, :ip_hash])

  defp check_ban(nil, changeset), do: changeset

  defp check_ban(hash, changeset) when is_binary(hash) do
    if banned?(hash) do
      Ash.Changeset.add_error(changeset, field: :banned, message: "posting is not allowed")
    else
      changeset
    end
  end

  # Deliberate `authorize?: false`: enforcement is a machine check internal
  # to the posting flow. Ban records stay staff-only through every other
  # read path (all Ban policies require a staff actor).
  defp banned?(poster_hash) do
    now = DateTime.utc_now()
    import Ash.Expr
    import Ash.Query, only: [filter: 2]

    query =
      AccelaImageboard.Moderation.Ban
      |> filter(expr(poster_hash == ^poster_hash and (is_nil(expires_at) or expires_at > ^now)))

    # Fail closed: if we cannot check, we do not allow the post.
    case Ash.read(query, authorize?: false) do
      {:ok, []} -> false
      {:ok, _banned} -> true
      {:error, _reason} -> true
    end
  end
end
