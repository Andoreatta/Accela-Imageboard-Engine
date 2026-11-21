defmodule AccelaImageboardWeb.BoardLiveTest do
  @moduledoc """
  A board page: its threads in imageboard order, the new-thread form, and the ways
  the page says "no" - an unknown board, a hidden board, a board that takes threads
  from staff only.
  """

  use AccelaImageboardWeb.ConnCase, async: false

  import AccelaImageboard.DataCase
  import AccelaImageboardWeb.BoardCase
  import Phoenix.LiveViewTest

  alias AccelaImageboardWeb.Content

  describe "reading a board" do
    test "lists its threads with the pinned one on top", %{conn: conn} do
      board = create_board(slug: "tech", name: "Technology")
      _older = create_thread(board, subject: "Older thread")
      _newer = create_thread(board, subject: "Newer thread")
      pinned = create_thread(board, subject: "Pinned announcement")

      {:ok, _pinned} =
        Ash.update(pinned, %{pinned: true}, action: :staff_update, authorize?: false)

      {:ok, view, html} = live(unique_conn(conn, 1), "/b/#{board.slug}")

      assert has_element?(view, "#threads")
      assert html =~ "Pinned announcement"
      assert html =~ "Newer thread"
      assert html =~ "Older thread"

      pinned_at = position(html, "Pinned announcement")
      newer_at = position(html, "Newer thread")
      older_at = position(html, "Older thread")

      assert pinned_at < newer_at
      assert newer_at < older_at
    end

    test "shows the empty state on a board with no threads", %{conn: conn} do
      board = create_board(slug: "quiet")

      {:ok, _view, html} = live(unique_conn(conn, 2), "/b/#{board.slug}")

      assert html =~ "No threads yet. Be the first to start one."
    end

    test "pages through the threads with the keyset cursor", %{conn: conn} do
      board = create_board(slug: "busy")

      for index <- 1..21 do
        create_thread(board, subject: "Thread #{index}")
      end

      {:ok, view, _html} = live(unique_conn(conn, 3), "/b/#{board.slug}")

      assert has_element?(view, "#load-more-threads")

      view |> element("#load-more-threads") |> render_click()

      refute has_element?(view, "#load-more-threads")
    end
  end

  describe "a board that cannot be shown" do
    test "renders the not-found panel for an unknown slug", %{conn: conn} do
      {:ok, view, html} = live(unique_conn(conn, 4), "/b/does-not-exist")

      assert html =~ "Board not found"
      refute has_element?(view, "#new-thread-form")
    end

    test "renders the not-found panel for a hidden board", %{conn: conn} do
      create_board(slug: "secret", name: "Secret", hidden: true)

      {:ok, view, html} = live(unique_conn(conn, 5), "/b/secret")

      assert html =~ "Board not found"
      refute has_element?(view, "#new-thread-form")
    end

    test "hides the new-thread form on a staff-only board", %{conn: conn} do
      board = create_board(slug: "staff")

      {:ok, board} =
        Ash.update(board, %{staff_only_threads: true}, action: :update, authorize?: false)

      {:ok, view, html} = live(unique_conn(conn, 6), "/b/#{board.slug}")

      assert html =~ board.name
      refute has_element?(view, "#new-thread-form")
    end
  end

  describe "starting a thread" do
    test "creates the thread and navigates to it", %{conn: conn} do
      board = create_board(slug: "tech")

      {:ok, view, _html} = live(unique_conn(conn, 7), "/b/#{board.slug}")

      assert {:error, {:live_redirect, %{to: to}}} =
               view
               |> form("#new-thread-form", thread: %{subject: "Opening subject"})
               |> render_submit()

      assert to =~ "/b/#{board.slug}/t/"

      thread_id = to |> String.split("/") |> List.last()
      assert {:ok, thread} = Content.thread(board.id, thread_id)
      assert thread.subject == "Opening subject"
      assert thread.board_id == board.id
    end

    test "accepts a thread with no subject and keeps it untitled", %{conn: conn} do
      board = create_board(slug: "tech")

      {:ok, view, _html} = live(unique_conn(conn, 8), "/b/#{board.slug}")

      assert {:error, {:live_redirect, %{to: to}}} =
               view
               |> form("#new-thread-form", thread: %{subject: ""})
               |> render_submit()

      thread_id = to |> String.split("/") |> List.last()
      assert {:ok, thread} = Content.thread(board.id, thread_id)
      assert thread.subject in [nil, ""]

      {:ok, _view, html} = live(unique_conn(conn, 8), to)
      assert html =~ "Untitled thread"
    end
  end

  defp position(html, needle) do
    {start, _length} = :binary.match(html, needle)
    start
  end
end
