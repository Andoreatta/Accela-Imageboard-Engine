defmodule AccelaImageboardWeb.BoardIndexLiveTest do
  @moduledoc """
  The front page: every public board, nothing hidden, and a keyset "more" button
  that keeps working on a large catalog.
  """

  use AccelaImageboardWeb.ConnCase, async: false

  import AccelaImageboard.DataCase, only: [create_board: 1]
  import Phoenix.LiveViewTest

  test "lists the public boards with a link each", %{conn: conn} do
    create_board(slug: "tech", name: "Technology")
    create_board(slug: "music", name: "Music")

    {:ok, view, html} = live(conn, "/")

    assert html =~ "Technology"
    assert html =~ "Music"
    assert has_element?(view, ~s{a[href="/b/tech"]})
    assert has_element?(view, ~s{a[href="/b/music"]})
    assert has_element?(view, "#boards")
  end

  test "never lists a hidden board", %{conn: conn} do
    create_board(slug: "visible", name: "Visible")
    create_board(slug: "secret", name: "Secret", hidden: true)

    {:ok, view, _html} = live(conn, "/")

    assert has_element?(view, ~s{a[href="/b/visible"]})
    refute has_element?(view, ~s{a[href="/b/secret"]})
  end

  test "renders the empty state when no board is open", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/")

    assert html =~ "No boards are open yet."
  end

  test "pages through the catalog with the keyset cursor", %{conn: conn} do
    slugs =
      for index <- 0..12 do
        slug = "board-" <> String.pad_leading(Integer.to_string(index), 2, "0")
        create_board(slug: slug, name: "Board #{index}")
        slug
      end

    {:ok, view, _html} = live(conn, "/")

    first_page = Enum.take(slugs, 12)
    last_slug = List.last(slugs)

    for slug <- first_page do
      assert has_element?(view, ~s{a[href="/b/#{slug}"]})
    end

    refute has_element?(view, ~s{a[href="/b/#{last_slug}"]})
    assert has_element?(view, "#load-more-boards")

    view |> element("#load-more-boards") |> render_click()

    assert has_element?(view, ~s{a[href="/b/#{last_slug}"]})
    refute has_element?(view, "#load-more-boards")
  end
end
