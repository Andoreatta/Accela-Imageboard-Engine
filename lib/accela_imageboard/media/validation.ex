defmodule AccelaImageboard.Media.Validation do
  @moduledoc """
  Content validation for image uploads, decided by the bytes and never by the
  client.

  An upload is accepted only when all of the following hold:

    1. the file signature at offset 0 is one of the supported image formats
       (JPEG, PNG, GIF, WebP) - a declared `content-type` is only ever used as a
       cross-check, so a renamed `evil.html` or an `image/png` that is really an
       SVG is rejected;
    2. the size is within the configured bounds (see `limits/0`);
    3. the first kilobyte carries no markup that would make the payload a
       polyglot (HTML, SVG, PHP, XML entity declarations). Those are rejected
       even when the signature is valid, because the file is served from the
       same origin as the board.

  Limits are configurable and clamped to a hard ceiling, so a typo in the
  environment cannot turn the board into an unbounded file host:

      config :accela_imageboard, :media_upload,
        max_bytes: 10_485_760,
        min_bytes: 64
  """

  @config_key :media_upload

  # 10 MiB per file and 50 MiB absolute ceiling, whatever the config says.
  @default_max_bytes 10 * 1024 * 1024
  @hard_max_bytes 50 * 1024 * 1024
  @default_min_bytes 64

  # Enough to hold any signature plus the markup we screen for.
  @head_bytes 1024

  @extensions ~w(.jpg .jpeg .png .gif .webp)
  @content_types ~w(image/jpeg image/png image/gif image/webp)

  @markup [
    "<SCRIPT",
    "<HTML",
    "<SVG",
    "<IFRAME",
    "<OBJECT",
    "<?PHP",
    "<?XML",
    "<!DOCTYPE",
    "<!ENTITY"
  ]

  @type media :: %{
          kind: :jpeg | :png | :gif | :webp,
          content_type: String.t(),
          extension: String.t()
        }

  @typedoc "Reasons an upload is refused. Every one is safe to show to a user."
  @type error ::
          :empty_file
          | :unreadable_file
          | :too_small
          | :too_large
          | :unsupported_type
          | :content_type_mismatch
          | :suspicious_content

  @doc """
  File extensions accepted by the upload input, for `Phoenix.LiveView.allow_upload/3`.
  """
  @spec extensions() :: [String.t()]
  def extensions, do: @extensions

  @doc """
  MIME types this app is willing to store and serve, for `allow_upload/3` and the
  media controller.
  """
  @spec content_types() :: [String.t()]
  def content_types, do: @content_types

  @doc """
  Size bounds (in bytes) for a single upload, read from `:media_upload` config.

  `max_bytes` is clamped to a hard ceiling of #{@hard_max_bytes} bytes and never
  allowed below `min_bytes`.
  """
  @spec limits() :: %{max_bytes: pos_integer(), min_bytes: pos_integer()}
  def limits do
    config = Application.get_env(:accela_imageboard, @config_key, []) |> normalize_config()

    min_bytes = positive(config[:min_bytes], @default_min_bytes) |> min(@hard_max_bytes)

    max_bytes =
      config[:max_bytes]
      |> positive(@default_max_bytes)
      |> min(@hard_max_bytes)
      |> max(min_bytes)

    %{max_bytes: max_bytes, min_bytes: min_bytes}
  end

  @doc """
  Validates the file at `path`.

  `declared_content_type` is the type the client claimed; it is only used to
  reject a mismatch, never to decide what the file is. Returns `{:ok, media}` with
  the sniffed type, or `{:error, reason}`.
  """
  @spec validate(Path.t(), String.t() | nil) :: {:ok, media()} | {:error, error()}
  def validate(path, declared_content_type \\ nil) do
    with {:ok, %File.Stat{size: size}} <- stat(path),
         :ok <- check_size(size, limits()),
         {:ok, head} <- read_head(path),
         {:ok, kind} <- sniff(head),
         :ok <- check_declared(declared_content_type, kind),
         :ok <- check_markup(head) do
      {:ok, describe(kind)}
    end
  end

  defp stat(path) do
    case File.stat(path) do
      {:ok, %File.Stat{type: :regular} = stat} -> {:ok, stat}
      {:ok, _not_a_regular_file} -> {:error, :unreadable_file}
      {:error, _reason} -> {:error, :unreadable_file}
    end
  end

  defp check_size(0, _limits), do: {:error, :empty_file}
  defp check_size(size, %{min_bytes: min}) when size < min, do: {:error, :too_small}
  defp check_size(size, %{max_bytes: max}) when size > max, do: {:error, :too_large}
  defp check_size(_size, _limits), do: :ok

  # `path` is the upload temp file handed to the consume callback, not a request param.
  # sobelow_skip ["Traversal.FileModule"]
  defp read_head(path) do
    case File.open(path, [:read, :binary], fn file -> IO.binread(file, @head_bytes) end) do
      {:ok, head} when is_binary(head) and byte_size(head) > 0 -> {:ok, head}
      {:ok, _empty} -> {:error, :empty_file}
      {:error, _reason} -> {:error, :unreadable_file}
    end
  end

  # Signatures of every accepted format. Anything else is not an image we serve.
  defp sniff(<<0xFF, 0xD8, 0xFF, _rest::binary>>), do: {:ok, :jpeg}
  defp sniff(<<0x89, "PNG\r\n", 0x1A, "\n", _rest::binary>>), do: {:ok, :png}
  defp sniff(<<"GIF87a", _rest::binary>>), do: {:ok, :gif}
  defp sniff(<<"GIF89a", _rest::binary>>), do: {:ok, :gif}
  defp sniff(<<"RIFF", _size::binary-size(4), "WEBP", _rest::binary>>), do: {:ok, :webp}
  defp sniff(_head), do: {:error, :unsupported_type}

  defp check_declared(declared, kind) do
    case normalize_content_type(declared) do
      nil -> :ok
      ^kind -> :ok
      _other -> {:error, :content_type_mismatch}
    end
  end

  # `application/octet-stream` (and a missing header) carries no claim, so the
  # sniffed signature decides. Anything that does claim an image type must agree.
  defp normalize_content_type(nil), do: nil

  defp normalize_content_type(declared) when is_binary(declared) do
    declared
    |> String.split(";")
    |> hd()
    |> String.trim()
    |> String.downcase()
    |> declared_kind()
  end

  defp normalize_content_type(_declared), do: nil

  defp declared_kind(""), do: nil
  defp declared_kind("application/octet-stream"), do: nil
  defp declared_kind(type) when type in ["image/jpeg", "image/jpg", "image/pjpeg"], do: :jpeg
  defp declared_kind("image/png"), do: :png
  defp declared_kind("image/gif"), do: :gif
  defp declared_kind("image/webp"), do: :webp
  defp declared_kind(_other), do: :unknown

  defp check_markup(head) do
    upper = String.upcase(head)

    if Enum.any?(@markup, &String.contains?(upper, &1)) do
      {:error, :suspicious_content}
    else
      :ok
    end
  end

  defp describe(:jpeg), do: %{kind: :jpeg, content_type: "image/jpeg", extension: "jpg"}
  defp describe(:png), do: %{kind: :png, content_type: "image/png", extension: "png"}
  defp describe(:gif), do: %{kind: :gif, content_type: "image/gif", extension: "gif"}
  defp describe(:webp), do: %{kind: :webp, content_type: "image/webp", extension: "webp"}

  defp normalize_config(config) when is_list(config), do: Map.new(config)
  defp normalize_config(config) when is_map(config), do: config
  defp normalize_config(_config), do: %{}

  defp positive(value, _default) when is_integer(value) and value > 0, do: value
  defp positive(_value, default), do: default
end
