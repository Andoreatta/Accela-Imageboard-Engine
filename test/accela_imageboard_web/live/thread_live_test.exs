defmodule AccelaImageboardWeb.ThreadLiveTest do
  @moduledoc """
  The thread page: posts in insertion order, the reply flow (with and without an
  image), the anonymous attribution, and every way an upload is refused.

  Uploads write to a per-test temporary directory, so these tests run serially.
  """

  use AccelaImageboardWeb.ConnCase, async: false

  import AccelaImageboard.DataCase
  import AccelaImageboardWeb.BoardCase
  import Phoenix.LiveViewTest

  alias AccelaImageboard.Media.Storage
  alias AccelaImageboard.Security.IpHash
  alias AccelaImageboardWeb.Content

  setup do
    {:ok, uploads_dir: use_temporary_uploads_dir()}
  end

  describe "reading a thread" do
    test "renders its posts in insertion order", %{conn: conn} do
      %{board: board, thread: thread, op: op} = fixture()

      {:ok, second} = create_post(thread, body: "A second post")

      {:ok, view, html} = live(unique_conn(conn, 11), thread_path(board, thread))

      assert has_element?(view, "#posts")
      assert html =~ "Opening post"
      assert html =~ "A second post"
      assert has_element?(view, "#posts-#{op.id}")
      assert has_element?(view, "#posts-#{second.id}")

      assert position(html, "Opening post") < position(html, "A second post")
    end

    test "marks the opening post as the OP", %{conn: conn} do
      %{board: board, thread: thread, op: op} = fixture()

      {:ok, _view, html} = live(unique_conn(conn, 12), thread_path(board, thread))

      assert html =~ "posts-#{op.id}"
      assert html =~ "OP"
    end

    test "pages through a long thread with the keyset cursor", %{conn: conn} do
      %{board: board, thread: thread} = fixture()

      for index <- 1..26 do
        {:ok, _post} = create_post(thread, body: "Reply number #{index}")
      end

      {:ok, view, _html} = live(unique_conn(conn, 13), thread_path(board, thread))

      assert has_element?(view, "#load-more-posts")

      view |> element("#load-more-posts") |> render_click()

      refute has_element?(view, "#load-more-posts")
      assert has_element?(view, "#posts")
    end

    test "shows the not-found panel for an unknown thread", %{conn: conn} do
      board = create_board(slug: "tech")

      {:ok, _view, html} =
        live(unique_conn(conn, 14), "/b/#{board.slug}/t/00000000-0000-0000-0000-000000000000")

      assert html =~ "Thread not found"
    end

    test "shows the not-found panel for a thread of a hidden board", %{conn: conn} do
      board = create_board(slug: "secret", hidden: true)
      thread = create_thread(board)

      {:ok, _view, html} = live(unique_conn(conn, 15), thread_path(board, thread))

      assert html =~ "Thread not found"
    end

    test "offers no reply form on a locked thread", %{conn: conn} do
      %{board: board, thread: thread} = fixture()

      {:ok, _locked} =
        Ash.update(thread, %{locked: true}, action: :staff_update, authorize?: false)

      {:ok, view, html} = live(unique_conn(conn, 16), thread_path(board, thread))

      assert html =~ "This thread is closed."
      refute has_element?(view, "#reply-form")
    end
  end

  describe "replying" do
    test "creates a post attributed to the connection, never to the form", %{conn: conn} do
      conn = unique_conn(conn, 17)
      %{board: board, thread: thread} = fixture()

      {:ok, view, _html} = live(conn, thread_path(board, thread))

      html =
        view
        |> form("#reply-form", post: %{body: "hello from the test", name: "anon"})
        |> render_submit()

      assert html =~ "hello from the test"

      post = find_post(thread, "hello from the test")
      assert post.name == "anon"
      assert post.poster_hash == IpHash.hash(conn.remote_ip)
      assert has_element?(view, "#posts-#{post.id}")
    end

    test "a reply moves its thread back to the top of the board", %{conn: conn} do
      board = create_board(slug: "tech")
      older = create_thread(board, subject: "Older thread", body: "older op")
      _newer = create_thread(board, subject: "Newer thread", body: "newer op")

      {:ok, _board_view, before_html} = live(unique_conn(conn, 25), "/b/#{board.slug}")
      assert position(before_html, "Newer thread") < position(before_html, "Older thread")

      {:ok, view, _html} = live(unique_conn(conn, 26), thread_path(board, older))
      view |> form("#reply-form", post: %{body: "bump me"}) |> render_submit()

      {:ok, _bumped_view, after_html} = live(unique_conn(conn, 27), "/b/#{board.slug}")
      assert position(after_html, "Older thread") < position(after_html, "Newer thread")
    end

    test "ignores a poster hash smuggled in through the params", %{conn: conn} do
      conn = unique_conn(conn, 18)
      %{board: board, thread: thread} = fixture()

      {:ok, view, _html} = live(conn, thread_path(board, thread))

      view
      |> element("#reply-form")
      |> render_submit(%{post: %{body: "spoof attempt", poster_hash: "forged"}})

      post = find_post(thread, "spoof attempt")
      assert post.poster_hash == IpHash.hash(conn.remote_ip)
      refute post.poster_hash == "forged"
    end

    test "creates no post when the comment is blank", %{conn: conn} do
      %{board: board, thread: thread} = fixture()

      {:ok, view, _html} = live(unique_conn(conn, 19), thread_path(board, thread))

      html =
        view
        |> form("#reply-form", post: %{body: ""})
        |> render_submit()

      assert has_element?(view, "#reply-form")
      assert html =~ "required"
      assert length(posts_of(thread)) == 1
    end

    test "refuses a poster with an active ban and says so", %{conn: conn} do
      conn = unique_conn(conn, 20)
      %{board: board, thread: thread} = fixture()
      staff = create_staff_user()

      {:ok, _ban} =
        Ash.create(
          AccelaImageboard.Moderation.Ban,
          %{
            poster_hash: IpHash.hash(conn.remote_ip),
            reason: "spam",
            issued_by_id: staff.id
          },
          action: :ban,
          authorize?: false
        )

      {:ok, view, _html} = live(conn, thread_path(board, thread))

      html =
        view
        |> form("#reply-form", post: %{body: "ban evasion"})
        |> render_submit()

      assert html =~ "posting is not allowed"
      assert length(posts_of(thread)) == 1
    end
  end

  describe "replying with an image" do
    test "stores the bytes, attaches them and renders the image", %{conn: conn, uploads_dir: dir} do
      conn = unique_conn(conn, 21)
      %{board: board, thread: thread} = fixture()

      {:ok, view, _html} = live(conn, thread_path(board, thread))

      upload = file_input(view, "#reply-form", :image, [upload("pixel.png", png(), "image/png")])
      render_upload(upload, "pixel.png")

      html =
        view
        |> form("#reply-form", post: %{body: "with an image"})
        |> render_submit()

      post = find_post(thread, "with an image")
      assert [media] = post.media
      assert media.content_type == "image/png"
      assert media.byte_size == byte_size(png())
      assert media.original_filename == "pixel.png"

      assert {:ok, path} = Storage.read(media.storage_key)
      assert File.read!(path) == png()
      assert length(File.ls!(dir)) == 1

      assert html =~ "/media/#{media.id}"

      served = get(build_conn(), "/media/#{media.id}")
      assert served.status == 200
      assert response(served, 200) == png()
    end

    test "refuses an SVG disguised as a PNG and creates no post", %{
      conn: conn,
      uploads_dir: dir
    } do
      %{board: board, thread: thread} = fixture()

      {:ok, view, _html} = live(unique_conn(conn, 22), thread_path(board, thread))

      upload = file_input(view, "#reply-form", :image, [upload("evil.png", svg(), "image/png")])
      render_upload(upload, "evil.png")

      html =
        view
        |> form("#reply-form", post: %{body: "xss attempt"})
        |> render_submit()

      assert html =~ "Only JPEG, PNG, GIF and WebP images are allowed."
      assert length(posts_of(thread)) == 1
      assert File.ls!(dir) == []
    end

    test "refuses a text file that claims to be a JPEG", %{conn: conn, uploads_dir: dir} do
      %{board: board, thread: thread} = fixture()

      {:ok, view, _html} = live(unique_conn(conn, 23), thread_path(board, thread))

      upload =
        file_input(view, "#reply-form", :image, [upload("fake.jpg", fake_jpeg(), "image/jpeg")])

      render_upload(upload, "fake.jpg")

      html =
        view
        |> form("#reply-form", post: %{body: "not an image"})
        |> render_submit()

      assert html =~ "Only JPEG, PNG, GIF and WebP images are allowed."
      assert length(posts_of(thread)) == 1
      assert File.ls!(dir) == []
    end

    test "refuses a GIF/HTML polyglot", %{conn: conn, uploads_dir: dir} do
      %{board: board, thread: thread} = fixture()

      {:ok, view, _html} = live(unique_conn(conn, 24), thread_path(board, thread))

      upload =
        file_input(view, "#reply-form", :image, [
          upload("poly.gif", gif_html_polyglot(), "image/gif")
        ])

      render_upload(upload, "poly.gif")

      html =
        view
        |> form("#reply-form", post: %{body: "polyglot"})
        |> render_submit()

      assert html =~ "That file contains markup and was rejected."
      assert length(posts_of(thread)) == 1
      assert File.ls!(dir) == []
    end
  end

  ## fixtures

  defp fixture do
    board = create_board(slug: "tech", name: "Technology")
    thread = create_thread(board, subject: "A thread", body: "Opening post")
    [op] = posts_of(thread)

    %{board: board, thread: thread, op: op}
  end

  defp thread_path(board, thread), do: "/b/#{board.slug}/t/#{thread.id}"

  defp posts_of(thread) do
    {posts, _cursor} = Content.posts(thread.id)
    posts
  end

  defp find_post(thread, body) do
    thread
    |> posts_of()
    |> Enum.find(&(&1.body == body))
    |> case do
      nil -> flunk("no post with body #{inspect(body)} was created")
      post -> post
    end
  end

  defp position(html, needle) do
    {start, _length} = :binary.match(html, needle)
    start
  end
end
