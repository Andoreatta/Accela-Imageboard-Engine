defmodule AccelaImageboardWeb.Content do
  @moduledoc """
  Read side of the board UI: paginated access to the public reads of the
  `AccelaImageboard.Boards` domain.

  The domain owns the read actions - their filters, their ordering and, since the
  pagination work, their keyset pagination. This module therefore does not
  re-implement any of that: it asks for a page (`limit` + the cursor of the last row
  shown) and returns `{items, next_cursor}`, where `next_cursor` is `nil` on the last
  page.

  A cursor is opaque: it is the keyset metadata Ash attaches to the last record of a
  page (`record.__metadata__[:keyset]`), so it is stable against rows being inserted
  or deleted while somebody reads. Results are accepted as either an `Ash.Page`
  struct or a plain list, so the UI keeps working if an action ever stops being
  paginated.
  """

  import Ash.Expr

  require Ash.Query

  alias AccelaImageboard.Boards.Board
  alias AccelaImageboard.Boards.Post
  alias AccelaImageboard.Boards.Thread

  @default_boards_per_page 12
  @default_threads_per_page 20
  @default_posts_per_page 25

  # The thread rows show how much conversation a thread holds and which post opened
  # it; Ash only loads aggregates when asked, so every thread read asks.
  @thread_aggregates [:post_count, :first_post_id, :last_post_id]

  @typedoc "Opaque cursor for the boards listing."
  @type cursor :: String.t()

  @doc """
  Public boards, in the domain's order (slug ascending).

  Returns `{boards, next_cursor}`.
  """
  @spec boards(cursor() | nil, keyword()) :: {[Board.t()], cursor() | nil}
  def boards(cursor \\ nil, opts \\ []) do
    Board
    |> Ash.Query.for_read(:list_public)
    |> page(limit(opts, @default_boards_per_page), cursor)
    |> read_page()
  end

  @doc """
  Looks up a single visible board by slug.

  Returns `{:error, :not_found}` for an unknown or hidden board, so the LiveView can
  answer both with the same page.
  """
  @spec board(String.t()) :: {:ok, Board.t()} | {:error, :not_found}
  def board(slug) when is_binary(slug) do
    Board
    |> Ash.Query.for_read(:read)
    |> Ash.Query.filter(expr(slug == ^slug))
    |> Ash.Query.page(limit: 1)
    |> read_page()
    |> case do
      {[board], _cursor} -> {:ok, board}
      _empty -> {:error, :not_found}
    end
  end

  def board(_slug), do: {:error, :not_found}

  @doc """
  Threads of a board in imageboard order (pinned first, then most recently bumped),
  including the `post_count`/`first_post_id`/`last_post_id` aggregates.

  Returns `{threads, next_cursor}`.
  """
  @spec threads(String.t(), cursor() | nil, keyword()) :: {[Thread.t()], cursor() | nil}
  def threads(board_id, cursor \\ nil, opts \\ []) do
    Thread
    |> Ash.Query.for_read(:read)
    |> Ash.Query.filter(expr(board_id == ^board_id))
    |> Ash.Query.load(@thread_aggregates)
    |> page(limit(opts, @default_threads_per_page), cursor)
    |> read_page()
  end

  @doc """
  A single thread of a board, or `{:error, :not_found}` when it does not exist or
  belongs to a hidden board.
  """
  @spec thread(String.t(), String.t()) :: {:ok, Thread.t()} | {:error, :not_found}
  def thread(board_id, thread_id) do
    Thread
    |> Ash.Query.for_read(:read)
    |> Ash.Query.filter(expr(id == ^thread_id and board_id == ^board_id))
    |> Ash.Query.load(@thread_aggregates)
    |> Ash.Query.page(limit: 1)
    |> read_page()
    |> case do
      {[thread], _cursor} -> {:ok, thread}
      _empty -> {:error, :not_found}
    end
  end

  @doc """
  Visible posts of a thread in insertion order, with their attached media loaded.

  Returns `{posts, next_cursor}`; pass the cursor back to load the following (newer)
  posts of a long thread.
  """
  @spec posts(String.t(), cursor() | nil, keyword()) :: {[Post.t()], cursor() | nil}
  def posts(thread_id, cursor \\ nil, opts \\ []) do
    Post
    |> Ash.Query.for_read(:in_thread)
    |> Ash.Query.filter(expr(thread_id == ^thread_id))
    |> Ash.Query.load(:media)
    |> page(limit(opts, @default_posts_per_page), cursor)
    |> read_page()
  end

  ## pagination

  defp page(query, limit, nil), do: Ash.Query.page(query, limit: limit)
  defp page(query, limit, cursor), do: Ash.Query.page(query, limit: limit, after: cursor)

  defp read_page(query) do
    case Ash.read(query) do
      {:ok, %{results: results} = page} -> {results, next_cursor(page)}
      {:ok, results} when is_list(results) -> {results, nil}
      {:error, error} -> raise error
    end
  end

  # The cursor of the last row shown is what the next page asks for; when the domain
  # says there is nothing after this page, there is no cursor.
  defp next_cursor(%{more?: true, results: results}) when is_list(results) and results != [] do
    List.last(results).__metadata__[:keyset]
  end

  defp next_cursor(_page), do: nil

  defp limit(opts, default) do
    case Keyword.get(opts, :limit, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> default
    end
  end
end
