defmodule AccelaImageboard.Media.Checks.PostFlowAttach do
  @moduledoc """
  Authorizes attaching media only as part of the anonymous posting flow.

  Two conditions must hold, and both are server-side facts rather than user input:

    1. the changeset carries the `media_upload: %{post_flow: true}` context marker,
       which only the posting code path (`AccelaImageboardWeb.ThreadLive`) sets -
       the marker is never read from request parameters;
    2. the target post exists, is visible, and lives in a thread that is still open
       (not locked/archived, board visible and not staff-only).

  A standalone call to `Media.attach` therefore fails closed: no marker means no
  access, and a marker without a postable target post is refused too. Staff keep
  their own policy branch, so moderation and operations tooling is unaffected.
  """

  use Ash.Policy.SimpleCheck

  @impl Ash.Policy.Check
  def describe(_options), do: "media attached inside an authorized post flow"

  @impl Ash.Policy.SimpleCheck
  def match?(_actor, %{changeset: changeset}, _options) do
    post_flow?(changeset) and postable?(target_post_id(changeset))
  end

  defp post_flow?(changeset) do
    get_in(changeset.context || %{}, [:media_upload, :post_flow]) == true
  end

  defp target_post_id(changeset) do
    Ash.Changeset.get_argument(changeset, :post_id) ||
      Ash.Changeset.get_attribute(changeset, :post_id)
  end

  # Fail closed: anything other than a confirmed, visible post in an open thread
  # denies. `authorize?: false` is deliberate - this is a machine check inside the
  # posting flow, and every public read path re-checks policies on its own.
  defp postable?(nil), do: false

  defp postable?(post_id) do
    import Ash.Expr
    import Ash.Query, only: [filter: 2]

    AccelaImageboard.Boards.Post
    |> filter(
      expr(
        id == ^post_id and is_nil(deleted_at) and
          thread.locked == false and thread.archived == false and
          thread.board.hidden == false and thread.board.staff_only_threads == false
      )
    )
    |> Ash.read(authorize?: false)
    |> case do
      {:ok, [_post]} -> true
      _error_or_empty -> false
    end
  end
end
