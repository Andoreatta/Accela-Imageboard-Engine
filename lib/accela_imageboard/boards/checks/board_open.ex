defmodule AccelaImageboard.Boards.Checks.BoardOpen do
  @moduledoc """
  Authorizes anonymous thread creation when the target board is open
  (not hidden, not staff-only).

  The lookup is a plain read with `authorize?: false` (a machine check inside
  the posting flow, not a user read), so it copes with the board read action
  being paginated: a match may come back as a page. Anything other than
  exactly one open board denies — fail closed.
  """

  use Ash.Policy.SimpleCheck

  @impl Ash.Policy.Check
  def describe(_options), do: "target board is open for threads"

  @impl Ash.Policy.SimpleCheck
  def match?(_actor, %{changeset: changeset}, _options) do
    board_id =
      Ash.Changeset.get_argument(changeset, :board_id) ||
        Ash.Changeset.get_attribute(changeset, :board_id)

    case board_id do
      nil -> false
      board_id -> open_board?(board_id)
    end
  end

  defp open_board?(board_id) do
    import Ash.Expr
    import Ash.Query, only: [filter: 2]

    AccelaImageboard.Boards.Board
    |> filter(expr(id == ^board_id and hidden == false and staff_only_threads == false))
    |> Ash.read(authorize?: false)
    |> single_result?()
  end

  # Paginated actions return `{:ok, %Ash.Page{}}`; unpaginated ones a list.
  defp single_result?({:ok, %{results: [_one]}}), do: true
  defp single_result?({:ok, [_one]}), do: true
  defp single_result?(_no_match_or_error), do: false
end
