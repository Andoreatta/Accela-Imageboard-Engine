defmodule AccelaImageboard.Boards.Checks.BoardOpen do
  @moduledoc """
  Authorizes anonymous thread creation when the target board is open
  (not hidden, not staff-only).
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
      nil ->
        false

      board_id ->
        import Ash.Expr
        import Ash.Query, only: [filter: 2]

        AccelaImageboard.Boards.Board
        |> filter(expr(id == ^board_id and hidden == false and staff_only_threads == false))
        |> Ash.read(authorize?: false)
        |> case do
          {:ok, [_board]} -> true
          _ -> false
        end
    end
  end
end
