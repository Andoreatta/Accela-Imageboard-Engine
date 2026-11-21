defmodule AccelaImageboard.Boards.Changes.BumpThread do
  @moduledoc """
  Bumps the parent thread after a reply has been committed.

  This is the imageboard ordering contract that used to be staff-only: a new
  reply moves its thread to the top of the board. The bump is an
  `Ash.update(thread, :post_bump)` performed in an `after_transaction` hook,
  i.e. **after the reply's transaction has committed**, and it goes through the
  normal policy path — its only extra authority is the server-side
  `posting_flow: %{bump: true}` marker that
  `AccelaImageboard.Boards.Checks.ReplyBumpFlow` requires together with an open
  thread. There is no `authorize?: false` anywhere in this path.

  `:post_bump` stays atomic (`set_attribute(:bumped_at, ...)` implements Ash's
  `atomic/3`), so the bump is a single `UPDATE threads SET bumped_at = ...`.

  ## Why after the commit, and why a refused bump never loses the reply

  Two things can make the bump refuse even though the reply was authorized: the
  thread can be locked/archived in the window between the reply's authorization
  and the bump (staff locking it concurrently), and a thread of a hidden board
  is invisible to the public read used to fetch it. The reply has already been
  authorized and stored, so discarding it would throw away content the poster
  is allowed to create — the refusal is **logged and swallowed**, and the only
  consequence is that the thread keeps its previous position.

  That is also why the hook is `after_transaction` rather than `after_action`:
  a failing nested write inside the reply's own transaction rolls that
  transaction back (Ash rolls back to the enclosing transaction, not to a
  savepoint), which would take the reply with it. Running the bump after the
  commit is what makes "log and continue" actually possible.

  The trade-off, documented on purpose: the reply and its bump are not one
  atomic unit. A crash between the commit and the bump leaves the reply stored
  and the thread ordering stale, and two replies committed concurrently can
  apply their bumps in the opposite order. Both outcomes are benign for an
  imageboard (the next reply re-bumps the thread); losing a post is not.
  """

  use Ash.Resource.Change

  require Logger

  alias AccelaImageboard.Boards.Thread

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.after_transaction(changeset, fn changeset, result ->
      # Only a committed reply bumps its thread; a failed create has nothing to
      # order.
      case result do
        {:ok, post} -> bump(post.thread_id, changeset)
        _failed -> :ok
      end

      result
    end)
  end

  defp bump(thread_id, changeset) do
    with {:ok, thread} <- Ash.get(Thread, thread_id),
         {:ok, _bumped} <- update(thread, changeset) do
      :ok
    else
      {:error, error} -> log_refusal(thread_id, error)
    end
  end

  # The bump is a machine write on behalf of the reply, so it carries no actor:
  # the marker plus an open thread is the whole authority (see the check). Not
  # authorizing as the poster is what keeps a reply from resurrecting a locked
  # or archived thread, while staff keep their own `:post_bump` branch.
  defp update(thread, changeset) do
    [
      action: :post_bump,
      actor: nil,
      context: %{posting_flow: %{bump: true}}
    ]
    |> copy_authorize?(changeset)
    |> then(&Ash.update(thread, %{}, &1))
  end

  # A caller that runs without authorization (operator tooling, seeds, fixtures)
  # keeps doing so for the nested write; anything that goes through policies
  # keeps going through policies.
  defp copy_authorize?(opts, changeset) do
    case changeset.context[:private][:authorize?] do
      authorize? when is_boolean(authorize?) -> Keyword.put(opts, :authorize?, authorize?)
      _not_set -> opts
    end
  end

  defp log_refusal(thread_id, error) do
    Logger.info("post stored, thread bump refused for thread #{thread_id}: #{describe(error)}")
  end

  defp describe(error) when is_exception(error), do: Exception.message(error)
  defp describe(error), do: inspect(error)
end
