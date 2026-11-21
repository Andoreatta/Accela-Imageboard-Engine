defmodule AccelaImageboardWeb.BoardCase do
  @moduledoc """
  Helpers shared by the board UI tests.

  Two things every web test needs and that are easy to get wrong:

    * a **distinct peer address per test**, so the anonymous poster hash differs and
      hammer rate-limit buckets (ETS, shared by the whole test run) never collide
      between tests;
    * **real image fixtures** - small but structurally valid JPEG, PNG, GIF and WebP
      payloads, plus the hostile variants the upload path must refuse.

  Fixtures are built here instead of being checked in, so a test can state exactly
  which bytes it exercises.
  """

  import Plug.Conn, only: [put_req_header: 3]

  alias AccelaImageboard.Boards.Media
  alias AccelaImageboard.Media.Storage

  @doc """
  Returns a connection whose peer address is unique to `index`.

  Both halves of the identity are set, because the two entry points read the peer
  differently: HTTP goes through `conn.remote_ip`, while a LiveView gets its
  `:peer_data` from `conn.private[:live_view_connect_info]` (what
  `Phoenix.LiveViewTest` uses instead of the adapter's fixed test peer). Setting
  both keeps a test honest about "the same visitor" across HTTP and LiveView, and
  the unique address keeps hammer rate-limit buckets (ETS, shared by the whole test
  run) from colliding between tests.
  """
  def unique_conn(conn, index) do
    connect_as(conn, {10, 42, rem(index, 250), 7})
  end

  @doc """
  Pins the connection's peer address, for both the HTTP plug and LiveView paths.
  """
  def connect_as(conn, ip) do
    conn
    |> Map.put(:remote_ip, ip)
    |> Plug.Conn.put_private(:live_view_connect_info, %{
      peer_data: %{address: ip, port: 0, ssl_cert: nil},
      x_headers: [],
      session: %{}
    })
  end

  @doc "A structurally valid 1x1 PNG."
  def png do
    Base.decode64!(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    )
  end

  @doc "A structurally valid 1x1 JPEG."
  def jpeg do
    Base.decode64!(
      "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q=="
    )
  end

  @doc "A structurally valid 1x1 GIF, padded past the minimum upload size."
  def gif do
    Base.decode64!("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7") <>
      :binary.copy(<<0>>, 64)
  end

  @doc "A structurally valid (header-wise) WebP payload, padded past the minimum."
  def webp do
    payload = "VP8 " <> :binary.copy(<<0>>, 64)
    "RIFF" <> <<byte_size(payload)::little-32>> <> "WEBP" <> payload
  end

  @doc """
  An SVG document: an image to a human, refused by the upload path because it is
  markup and would execute in the board's origin.
  """
  def svg do
    """
    <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
      <script>alert(document.domain)</script>
    </svg>
    """
  end

  @doc """
  A polyglot: a valid GIF signature followed by an HTML payload.

  The signature check alone would accept it, which is exactly why the validator also
  screens the first kilobyte for markup.
  """
  def gif_html_polyglot do
    "GIF89a" <> :binary.copy(<<0>>, 32) <> "<html><script>alert(1)</script></html>"
  end

  @doc """
  A file that claims to be a JPEG (`image/jpeg`) but is plain text, i.e. a renamed
  script.
  """
  def fake_jpeg do
    :binary.copy("not really a jpeg, just text. ", 4)
  end

  @doc """
  Writes `bytes` to a temporary file and returns its path, for the validator and
  storage tests. The file is removed when the test process exits.
  """
  def temp_file(bytes, name \\ "upload.bin") do
    dir = Path.join(System.tmp_dir!(), "accela-fixtures-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    path = Path.join(dir, name)
    File.write!(path, bytes)

    ExUnit.Callbacks.on_exit(fn -> File.rm_rf(dir) end)

    path
  end

  @doc """
  Points `:uploads_dir` at a fresh temporary directory for the duration of the test,
  and restores the previous value afterwards.
  """
  def use_temporary_uploads_dir do
    dir = Path.join(System.tmp_dir!(), "accela-uploads-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    previous = Application.get_env(:accela_imageboard, :uploads_dir)
    Application.put_env(:accela_imageboard, :uploads_dir, dir)

    ExUnit.Callbacks.on_exit(fn ->
      File.rm_rf(dir)

      case previous do
        nil -> Application.delete_env(:accela_imageboard, :uploads_dir)
        value -> Application.put_env(:accela_imageboard, :uploads_dir, value)
      end
    end)

    dir
  end

  @doc """
  Builds the upload entry map `Phoenix.LiveViewTest.file_input/4` expects.
  """
  def upload(name, content, content_type) do
    %{name: name, content: content, type: content_type}
  end

  @doc """
  Adds a header to a connection, used by the client-IP tests.
  """
  def with_header(conn, name, value), do: put_req_header(conn, name, value)

  @doc """
  Stores `bytes` on disk and creates the matching `Media` row for `post`.

  Attaching media is normally only possible from inside the post flow, so tests
  that only need a stored image (serving, headers, path safety) create the row
  with `authorize?: false`: they exercise the controller, not the attach policy.
  """
  def create_media(post, bytes, opts \\ []) do
    content_type = Keyword.get(opts, :content_type, "image/png")
    extension = Keyword.get(opts, :extension, "png")
    source = temp_file(bytes, "source.#{extension}")

    {:ok, stored} =
      Storage.store(
        source,
        %{extension: extension, content_type: content_type},
        "source.#{extension}"
      )

    stored
    |> Map.put(:post_id, post.id)
    |> then(&Ash.create(Media, &1, action: :attach, authorize?: false))
    |> case do
      {:ok, media} -> media
      {:error, error} -> raise "could not create media fixture: #{inspect(error)}"
    end
  end

  @doc """
  Creates a `Media` row that points at an arbitrary `storage_key`, without any file.

  Used to prove that a hand-written (or tampered) key can never reach the
  filesystem, even when it is the only thing standing between the database and
  `File` calls.
  """
  def create_media_with_key(post, storage_key, opts \\ []) do
    attrs = %{
      post_id: post.id,
      storage_key: storage_key,
      content_type: Keyword.get(opts, :content_type, "image/png"),
      byte_size: Keyword.get(opts, :byte_size, 68),
      sha256:
        Keyword.get_lazy(opts, :sha256, fn -> Base.encode16(:crypto.strong_rand_bytes(32)) end)
    }

    case Ash.create(Media, attrs, action: :attach, authorize?: false) do
      {:ok, media} -> media
      {:error, error} -> raise "could not create media fixture: #{inspect(error)}"
    end
  end
end
