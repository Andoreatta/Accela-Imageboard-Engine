defmodule AccelaImageboard.Boards.Checks.ThreadOpen do
  @moduledoc """
  Authorizes anonymous posting when the target thread is open.

  A policy like `expr(thread.locked == false)` cannot be evaluated on create
  (the parent relationship is not loaded on the new record), so this check
  looks the thread up explicitly.

  The lookup is a plain read with `authorize?: false` (it is a machine check
  inside the posting flow, not a user read), so it must cope with the thread
  read action being paginated: a match may come back as a page. Anything other
  than exactly one confirmed open, visible thread denies — fail closed.
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
    |> single_result?()
  end

  # Paginated actions return `{:ok, %Ash.Page{}}`; unpaginated ones a list.
  defp single_result?({:ok, %{results: [_one]}}), do: true
  defp single_result?({:ok, [_one]}), do: true
  defp single_result?(_no_match_or_error), do: false
end
