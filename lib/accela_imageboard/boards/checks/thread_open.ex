defmodule AccelaImageboard.Boards.Checks.ThreadOpen do
  @moduledoc """
  Authorizes anonymous posting when the target thread is open.

  A policy like `expr(thread.locked == false)` cannot be evaluated on create
  (the parent relationship is not loaded on the new record), so this check
  looks the thread up explicitly.
  """

  use Ash.Policy.SimpleCheck

  @impl Ash.Policy.Check
  def describe(_options) do
    "target thread is open (not locked/archived, board visible)"
  end

  @impl Ash.Policy.SimpleCheck
  def match?(_actor, %{changeset: changeset}, _options) do
    changeset
    |> target_thread_id()
    |> open_thread?()
  end

  defp target_thread_id(changeset) do
    Ash.Changeset.get_argument(changeset, :thread_id) ||
      Ash.Changeset.get_attribute(changeset, :thread_id)
  end

  # Fail closed: anything other than a confirmed open thread denies.
  defp open_thread?(nil), do: false

  defp open_thread?(thread_id) do
    import Ash.Expr
    import Ash.Query, only: [filter: 2]

    AccelaImageboard.Boards.Thread
    |> filter(
      expr(
        id == ^thread_id and locked == false and archived == false and
          board.hidden == false and board.staff_only_threads == false
      )
    )
    |> Ash.read(authorize?: false)
    |> case do
      {:ok, [_thread]} -> true
      _ -> false
    end
  end
end
