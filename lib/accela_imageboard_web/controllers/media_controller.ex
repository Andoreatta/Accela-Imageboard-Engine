defmodule AccelaImageboardWeb.MediaController do
  @moduledoc """
  Serves uploaded images at `/media/:id`.

  Images are never served statically: this controller reads the row, resolves the
  file through `AccelaImageboard.Media.Storage` - which only accepts keys it could
  have generated, so a traversal attempt never reaches the filesystem - and answers
  with the content type stored at upload time, `nosniff`, and an immutable cache
  header (the bytes behind an id never change).

  Unknown ids, malformed ids, missing rows, missing files and anything whose stored
  content type is outside the upload allow-list all produce the same 404, so the
  endpoint reveals nothing about what exists.

  Anti-hotlinking is handled globally by the `Cross-Origin-Resource-Policy:
  same-origin` header from `AccelaImageboardWeb.Plugs.SecureHeaders`.
  """

  use AccelaImageboardWeb, :controller

  alias AccelaImageboard.Boards.Media
  alias AccelaImageboard.Media.Storage
  alias AccelaImageboard.Media.Validation

  @id_regex ~r/\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/

  @doc "Sends the bytes of one attachment."
  # The filesystem path is rebuilt from the stored key and the content type is
  # allow-listed: both come from a validated row, never from the request.
  # sobelow_skip ["Traversal.SendFile", "XSS.ContentType"]
  def show(conn, %{"id" => id}) do
    with true <- Regex.match?(@id_regex, id),
         {:ok, media} <- fetch_media(id),
         {:ok, path} <- Storage.read(media.storage_key) do
      conn
      |> put_resp_content_type(media.content_type, nil)
      |> put_resp_header("cache-control", "public, max-age=31536000, immutable")
      |> put_resp_header("x-content-type-options", "nosniff")
      # `path` comes from `Storage.read/1`: a filesystem path is only ever rebuilt from a
      # `storage_key` read out of the database and re-validated against the key shape.
      |> send_file(200, path)
    else
      _missing_or_invalid -> not_found(conn)
    end
  end

  def show(conn, _params), do: not_found(conn)

  defp fetch_media(id) do
    case Ash.get(Media, id) do
      {:ok, %Media{} = media} ->
        if media.content_type in Validation.content_types(), do: {:ok, media}, else: :error

      _missing ->
        :error
    end
  end

  defp not_found(conn) do
    conn
    |> put_resp_content_type("text/plain")
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("x-content-type-options", "nosniff")
    |> send_resp(404, "Not found")
  end
end
