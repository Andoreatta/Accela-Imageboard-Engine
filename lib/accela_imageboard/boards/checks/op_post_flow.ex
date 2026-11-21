defmodule AccelaImageboard.Boards.Checks.OpPostFlow do
  @moduledoc """
  Authorizes creating a thread's opening post (the OP).

  The OP is not something a client asks for: `AccelaImageboard.Boards.Thread`'s
  `:create` action creates it itself, inside the same transaction, through
  `AccelaImageboard.Boards.Changes.CreateOpPost`, and marks that call with a
  server-side context marker:

      context: %{posting_flow: %{op: true, thread_id: thread.id}}

  Three conditions must hold, and all three are server-side facts:

    1. the marker is present and says this create is an OP (`:op` is `true`) —
       it is never read from request parameters;
    2. the marker names the same thread the post targets, so a marker minted
       for one thread cannot be replayed against another;
    3. the target thread is open — delegated to
       `AccelaImageboard.Boards.Checks.ThreadOpen` (not locked, not archived,
       board visible and not staff-only), so an OP cannot be dropped into a
       thread that stopped accepting posts.

  A standalone call to `Post`'s `:create_op` action therefore fails closed: no
  marker, a marker for another thread, or a closed thread all deny. There is
  deliberately **no staff branch** — staff create OPs through the same
  thread-creation flow as everyone else, and their extra authority over threads
  lives in `:post_bump`/`:staff_update`, not in inventing an OP.
  """

  use Ash.Policy.SimpleCheck

  alias AccelaImageboard.Boards.Checks.ThreadOpen

  @impl Ash.Policy.Check
  def describe(_options), do: "opening post created by its own thread-creation flow"

  @impl Ash.Policy.SimpleCheck
  def match?(_actor, %{changeset: changeset}, _options) do
    thread_id = target_thread_id(changeset)

    is_binary(thread_id) and
      marker?(posting_flow(changeset), thread_id) and
      ThreadOpen.match?(nil, %{changeset: changeset}, [])
  end

  # Fail closed on every other shape of the marker.
  defp marker?(%{op: true, thread_id: thread_id}, thread_id), do: true
  defp marker?(_marker, _thread_id), do: false

  defp posting_flow(changeset), do: get_in(changeset.context || %{}, [:posting_flow])

  defp target_thread_id(changeset) do
    Ash.Changeset.get_argument(changeset, :thread_id) ||
      Ash.Changeset.get_attribute(changeset, :thread_id)
  end
end
