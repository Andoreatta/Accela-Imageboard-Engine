defmodule AccelaImageboard.PaginationTest do
  @moduledoc """
  Unbounded reads are impossible on the public list actions.

  * `Board :read` / `:list_public`, `Thread :read` and `Post :in_thread` are
    keyset paginated (`default_limit: 25`, not countable), so a plain read
    returns an `%Ash.Page.Keyset{}` and a page never costs a `COUNT`.
  * the staff actions (`Post :moderation_queue`, `Board`/`Thread :staff_read`)
    are offset paginated (`default_limit: 50`) with a count.
  * `Ash.get/3` and relationship loads are exempt (Ash skips pagination when
    loading a relationship), so nothing that resolves a single record or a
    thread's posts changes behaviour.
  """

  use AccelaImageboard.DataCase, async: true

  require Ash.Query

  alias AccelaImageboard.Boards

  # Rate limits are per hashed identity, so every created row uses its own.
  defp create_boards(count) do
    for i <- 1..count do
      {:ok, board} =
        Ash.create(
          Boards.Board,
          %{slug: "p#{String.pad_leading(to_string(i), 3, "0")}", name: "Board #{i}"},
          authorize?: false
        )

      board
    end
  end

  defp create_threads(board, count) do
    for i <- 1..count do
      create_thread(board, subject: "thread #{i}")
    end
  end

  defp create_posts(thread, count) do
    for i <- 1..count do
      {:ok, post} = create_post(thread, body: "post #{i}")
      post
    end
  end

  defp keyset_of(%{__metadata__: %{keyset: keyset}}), do: keyset

  # Scoped to a test's own slugs: assertions must not depend on what else the
  # (shared) test database happens to contain.
  defp own_boards(min_slug, max_slug) do
    Ash.Query.filter(Boards.Board, slug >= ^min_slug and slug <= ^max_slug)
  end

  describe "board list" do
    test "returns a keyset page bounded by the default limit" do
      create_boards(30)

      assert {:ok, page} =
               own_boards("p001", "p030")
               |> Ash.read(action: :list_public, actor: nil)

      assert %Ash.Page.Keyset{} = page
      assert page.limit == 25
      assert length(page.results) == 25
      assert page.more?
      # Public pages are not countable: no COUNT query per page.
      assert is_nil(page.count)
    end

    test "walks to the next page with the last record's keyset" do
      create_boards(30)

      first_page = own_boards("p001", "p030") |> Ash.read!(action: :list_public, actor: nil)
      first_ids = Enum.map(first_page.results, & &1.id)

      second_page =
        own_boards("p001", "p030")
        |> Ash.read!(
          action: :list_public,
          actor: nil,
          page: [after: keyset_of(List.last(first_page.results))]
        )

      assert %Ash.Page.Keyset{} = second_page
      assert length(second_page.results) == 5
      refute second_page.more?

      second_ids = Enum.map(second_page.results, & &1.id)
      assert MapSet.disjoint?(MapSet.new(first_ids), MapSet.new(second_ids))
      assert length(Enum.uniq(first_ids ++ second_ids)) == 30
    end

    test "the primary read is paginated too, so no board read is unbounded" do
      create_boards(3)

      assert %Ash.Page.Keyset{limit: 25} = page = Ash.read!(Boards.Board, actor: nil)
      # ... while getting a single board is not a page.
      board = hd(page.results)
      assert %Boards.Board{} = Ash.get!(Boards.Board, board.id, actor: nil)
    end
  end

  describe "thread list of a board" do
    test "is keyset paginated in imageboard order (pinned first, then bumped)" do
      board = create_board()
      threads = create_threads(board, 30)

      # Pin the oldest thread: it must come first regardless of bump order.
      pinned = List.first(threads)

      {:ok, _pinned} =
        Ash.update(pinned, %{pinned: true}, action: :staff_update, actor: create_staff_user())

      page =
        Boards.Thread
        |> Ash.Query.filter(board_id == ^board.id)
        |> Ash.read!(actor: nil)

      assert %Ash.Page.Keyset{} = page
      assert page.limit == 25
      assert length(page.results) == 25
      assert page.more?
      assert hd(Enum.map(page.results, & &1.id)) == pinned.id

      remaining =
        Boards.Thread
        |> Ash.Query.filter(board_id == ^board.id)
        |> Ash.read!(actor: nil, page: [after: keyset_of(List.last(page.results))])

      assert length(remaining.results) == 5
      refute remaining.more?
    end

    test "relationship loads are not truncated by pagination" do
      board = create_board()
      threads = create_threads(board, 30)

      loaded = Ash.load!(board, :threads, actor: nil)

      assert length(loaded.threads) == 30

      assert Enum.map(loaded.threads, & &1.id) |> Enum.sort() ==
               Enum.map(threads, & &1.id) |> Enum.sort()
    end
  end

  describe "posts of a thread" do
    test "are keyset paginated oldest first" do
      thread = create_thread(create_board())
      # `create_thread` already stored the thread's opening post.
      op = thread |> Ash.load!(:posts, actor: nil) |> Map.fetch!(:posts) |> hd()
      posts = [op | create_posts(thread, 30)]

      page =
        Boards.Post
        |> Ash.Query.filter(thread_id == ^thread.id)
        |> Ash.read!(action: :in_thread, actor: nil)

      assert %Ash.Page.Keyset{} = page
      assert page.limit == 25
      assert length(page.results) == 25
      assert page.more?
      assert Enum.map(page.results, & &1.id) == Enum.map(Enum.take(posts, 25), & &1.id)

      rest =
        Boards.Post
        |> Ash.Query.filter(thread_id == ^thread.id)
        |> Ash.read!(
          action: :in_thread,
          actor: nil,
          page: [after: keyset_of(List.last(page.results))]
        )

      assert length(rest.results) == 6
      refute rest.more?
      assert Enum.map(rest.results, & &1.id) == Enum.map(Enum.drop(posts, 25), & &1.id)
    end

    test "the moderation queue is offset paginated with a count" do
      staff = create_staff_user()
      thread = create_thread(create_board())
      create_posts(thread, 3)

      page =
        Boards.Post
        |> Ash.Query.filter(thread_id == ^thread.id)
        |> Ash.read!(action: :moderation_queue, actor: staff, page: [limit: 2])

      assert %Ash.Page.Offset{} = page
      assert length(page.results) == 2
      # The thread's opening post plus the three replies.
      assert page.count == 4
      assert page.more?
    end
  end
end
