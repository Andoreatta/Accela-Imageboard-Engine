defmodule AccelaImageboardWeb.MediaControllerTest do
  @moduledoc """
  Serving is the part of the upload path an attacker can poke at directly, so the
  tests pin the headers (typed, nosniff, immutable), the exact bytes served, and
  the promise that every unusable request looks identical: a plain 404.
  """

  use AccelaImageboardWeb.ConnCase, async: false

  import AccelaImageboard.DataCase
  import AccelaImageboardWeb.BoardCase

  alias AccelaImageboard.Media.Storage

  setup do
    use_temporary_uploads_dir()

    board = create_board()
    thread = create_thread(board)
    {:ok, post} = create_post(thread)

    {:ok, post: post}
  end

  describe "GET /media/:id" do
    test "serves the stored bytes with a safe, cacheable response", %{conn: conn, post: post} do
      bytes = png()
      media = create_media(post, bytes)

      conn = get(conn, "/media/#{media.id}")

      assert conn.status == 200
      assert response(conn, 200) == bytes
      assert get_resp_header(conn, "content-type") == ["image/png"]
      assert get_resp_header(conn, "cache-control") == ["public, max-age=31536000, immutable"]
      assert get_resp_header(conn, "x-content-type-options") == ["nosniff"]
    end

    test "serves each allow-listed type with its own content type", %{conn: conn, post: post} do
      for {bytes, content_type, extension} <- [
            {jpeg(), "image/jpeg", "jpg"},
            {gif(), "image/gif", "gif"},
            {webp(), "image/webp", "webp"}
          ] do
        media = create_media(post, bytes, content_type: content_type, extension: extension)

        conn = get(conn, "/media/#{media.id}")

        assert conn.status == 200
        assert response(conn, 200) == bytes
        assert get_resp_header(conn, "content-type") == [content_type]
      end
    end

    test "is idempotent for the same id", %{conn: conn, post: post} do
      media = create_media(post, png())

      first = get(conn, "/media/#{media.id}")
      second = get(build_conn(), "/media/#{media.id}")

      assert response(first, 200) == response(second, 200)
    end
  end

  describe "GET /media/:id for anything else" do
    test "404s for an unknown id", %{conn: conn} do
      conn = get(conn, "/media/00000000-0000-0000-0000-000000000000")

      assert conn.status == 404
      assert conn.resp_body == "Not found"
      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "x-content-type-options") == ["nosniff"]
    end

    test "404s for a malformed id", %{conn: conn} do
      conn = get(conn, "/media/not-an-id")

      assert conn.status == 404
    end

    test "404s for a percent-encoded traversal in the id", %{conn: conn} do
      conn = get(conn, "/media/..%2F..%2F..%2Fetc%2Fpasswd")

      assert conn.status == 404
      assert conn.resp_body == "Not found"
    end

    test "404s when the row's storage key tries to escape the uploads directory", %{
      conn: conn,
      post: post
    } do
      for key <- ["../../../etc/passwd", "..\\..\\windows\\win.ini", "/etc/passwd", "nope.png"] do
        media = create_media_with_key(post, key)

        conn = get(conn, "/media/#{media.id}")

        assert conn.status == 404, "expected #{inspect(key)} to be refused"
      end
    end

    test "404s when the stored content type is outside the allow-list", %{conn: conn, post: post} do
      media =
        create_media_with_key(post, String.duplicate("a", 32) <> ".png",
          content_type: "image/svg+xml"
        )

      conn = get(conn, "/media/#{media.id}")

      assert conn.status == 404
    end

    test "404s when the row exists but the file is gone", %{conn: conn, post: post} do
      media = create_media(post, png())
      {:ok, path} = Storage.read(media.storage_key)
      File.rm!(path)

      conn = get(conn, "/media/#{media.id}")

      assert conn.status == 404
    end
  end

  describe "anonymous access" do
    test "serving needs no session and sets no cookies", %{conn: conn, post: post} do
      media = create_media(post, png())

      conn = get(conn, "/media/#{media.id}")

      assert conn.status == 200
      assert get_resp_header(conn, "set-cookie") == []
    end
  end
end
