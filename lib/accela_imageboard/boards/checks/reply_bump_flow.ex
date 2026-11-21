defmodule AccelaImageboard.Boards.Checks.ReplyBumpFlow do
  @moduledoc """
  Authorizes bumping a thread from the reply flow that just stored a post.

  Before this check, only staff could bump (`:post_bump` was staff-only), so an
  anonymous reply never brought its thread back to the top of the board. The
  bump is performed by
  `AccelaImageboard.Boards.Changes.BumpThread` — an
  `Ash.update(thread, :post_bump)` that runs, in the reply's transaction, right
  after the post row exists — and it authorizes like this:

    1. the update carries the server-side marker
       `context: %{posting_flow: %{bump: true}}`, which only the reply flow
       sets (never request parameters); and
    2. the thread being bumped is open: `locked == false` and
       `archived == false`, read from the loaded record, so the decision needs
       no second query.

  Two consequences are intentional:

    * the bump is a **machine write on behalf of the reply**, not on behalf of
      the poster. The bump update runs with a `nil` actor, so a locked or
      archived thread never moves — not even when a staff member is the one
      replying (staff keep their own `:post_bump` branch to bump on purpose);
    * a direct `Ash.update(thread, :post_bump)` by an anonymous actor has no
      marker and is refused.
  """

  use Ash.Policy.SimpleCheck

  @impl Ash.Policy.Check
  def describe(_options), do: "thread bump from the reply flow on an open thread"

  @impl Ash.Policy.SimpleCheck
  def match?(_actor, %{changeset: changeset}, _options) do
    bump_marker?(changeset) and open?(changeset.data)
  end

  defp bump_marker?(changeset) do
    get_in(changeset.context || %{}, [:posting_flow, :bump]) == true
  end

  # Fail closed: an unloaded or unexpected thread is not bumpable.
  defp open?(%{locked: false, archived: false}), do: true
  defp open?(_thread), do: false
end
