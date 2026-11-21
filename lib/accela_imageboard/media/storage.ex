defmodule AccelaImageboard.Media.Storage do
  @moduledoc """
  Filesystem storage for validated image uploads.

  Files are written flat under one root directory (configure it with
  `config :accela_imageboard, :uploads_dir, "/srv/accela/uploads"`; the default is
  `./uploads` resolved against the current working directory, which is the project
  root in development and the release root in production). Each file gets a random
  128-bit hex name plus the extension of the *sniffed* type, e.g.
  `7f3c...c1.jpg`, and its SHA-256 is computed while copying so the database can
  deduplicate and detect corruption.

  Path safety: a filesystem path is only ever built from a `storage_key` read back
  from the database, and that key is re-validated against a strict shape before it
  is joined to the root. Traversal sequences therefore cannot reach the filesystem,
  and the resolved path is checked to still live inside the root.
  """

  @key_regex ~r/\A[0-9a-f]{32}\.(?:jpg|jpeg|png|gif|webp)\z/
  @chunk_size 65_536

  @typedoc """
  What `store/3` returns; persisted through the `Media` resource's `:attach` action.
  """
  @type stored :: %{
          storage_key: String.t(),
          sha256: String.t(),
          byte_size: non_neg_integer(),
          content_type: String.t(),
          original_filename: String.t() | nil
        }

  @doc """
  Absolute path of the directory that holds the uploaded files.

  Read from `:uploads_dir`; defaults to `./uploads` under the current working
  directory. The directory is created lazily on the first write.
  """
  @spec root() :: Path.t()
  def root do
    case Application.get_env(:accela_imageboard, :uploads_dir) do
      path when is_binary(path) and path != "" -> Path.expand(path)
      _unset -> Path.join(File.cwd!(), "uploads")
    end
  end

  @doc """
  Copies `source_path` (a `Plug.Upload` temporary file) into storage.

  `media` is the value returned by `AccelaImageboard.Media.Validation.validate/2`;
  `original_filename` is kept for display only and never influences the storage
  path. Returns the metadata the `Media` resource stores.
  """
  @spec store(Path.t(), AccelaImageboard.Media.Validation.media(), String.t() | nil) ::
          {:ok, stored()} | {:error, :storage_failure}
  def store(source_path, %{extension: extension, content_type: content_type}, original_filename) do
    storage_key = storage_key(extension)
    destination = Path.join(root(), storage_key)

    with {:ok, sha256} <- sha256(source_path),
         :ok <- ensure_root(),
         :ok <- copy(source_path, destination),
         {:ok, %File.Stat{size: size}} <- File.stat(destination) do
      {:ok,
       %{
         storage_key: storage_key,
         sha256: sha256,
         byte_size: size,
         content_type: content_type,
         original_filename: original_filename
       }}
    else
      _failure -> {:error, :storage_failure}
    end
  end

  @doc """
  Resolves a `storage_key` to a readable path.

  Returns `{:error, :not_found}` for a key that is malformed (a traversal attempt,
  for instance) and for a key whose file is gone - the serving layer turns both into
  a 404 so it never reveals which of the two happened.
  """
  @spec read(String.t()) :: {:ok, Path.t()} | {:error, :not_found}
  def read(storage_key) do
    case path(storage_key) do
      {:ok, file} -> if File.regular?(file), do: {:ok, file}, else: {:error, :not_found}
      {:error, :invalid_key} -> {:error, :not_found}
    end
  end

  @doc """
  Builds the filesystem path for a `storage_key`, refusing anything that does not
  look like a key this module generated (see `valid_key?/1`).

  The resolved path is also required to stay inside `root/0`, which makes a
  traversal attempt impossible even if the key format rule were loosened later.
  """
  @spec path(String.t()) :: {:ok, Path.t()} | {:error, :invalid_key}
  def path(storage_key) when is_binary(storage_key) do
    root = root()
    candidate = Path.expand(Path.join(root, storage_key))

    if valid_key?(storage_key) and inside?(candidate, root) do
      {:ok, candidate}
    else
      {:error, :invalid_key}
    end
  end

  def path(_storage_key), do: {:error, :invalid_key}

  @doc """
  Deletes a stored file, used to roll back when the post it belongs to could not be
  created. A file that is already gone is not an error.
  """
  @spec delete(String.t()) :: :ok | {:error, :invalid_key}
  # The path comes from `path/1`, which only accepts keys this module could have
  # produced, so nothing request-shaped can reach `File.rm/1`.
  # sobelow_skip ["Traversal.FileModule"]
  def delete(storage_key) do
    case path(storage_key) do
      {:ok, file} ->
        _ = File.rm(file)
        :ok

      {:error, :invalid_key} ->
        {:error, :invalid_key}
    end
  end

  @doc """
  True when `key` is a storage key this module could have generated.

  This is the single definition of "safe key", used by `path/1`, the serving layer
  and the tests.
  """
  @spec valid_key?(term()) :: boolean()
  def valid_key?(key) when is_binary(key), do: Regex.match?(@key_regex, key)
  def valid_key?(_key), do: false

  @doc """
  SHA-256 of a file, hex encoded and streamed, so a large upload is never read whole.
  """
  @spec sha256(Path.t()) :: {:ok, String.t()} | {:error, :storage_failure}
  def sha256(path) do
    digest =
      path
      |> File.stream!(@chunk_size, [])
      |> Enum.reduce(:crypto.hash_init(:sha256), fn chunk, state ->
        :crypto.hash_update(state, chunk)
      end)
      |> :crypto.hash_final()

    {:ok, Base.encode16(digest, case: :lower)}
  rescue
    _file_error -> {:error, :storage_failure}
  end

  defp storage_key(extension) do
    Base.encode16(:crypto.strong_rand_bytes(16), case: :lower) <> "." <> extension
  end

  # Separator agnostic: a path that cannot be made relative to the root (or that
  # tries to climb out of it) is not inside the root.
  defp inside?(candidate, root) do
    relative = Path.relative_to(candidate, root)
    relative != candidate and not String.starts_with?(relative, "..")
  end

  # `root/0` is configuration (the uploads directory), never request data.
  # sobelow_skip ["Traversal.FileModule"]
  defp ensure_root do
    case File.mkdir_p(root()) do
      :ok -> :ok
      {:error, _reason} -> {:error, :storage_failure}
    end
  end

  # `destination` is built from a storage key this module generated; `source_path`
  # is the Plug upload temp file. Neither is user-controlled.
  # sobelow_skip ["Traversal.FileModule"]
  defp copy(source_path, destination) do
    case File.cp(source_path, destination) do
      :ok -> :ok
      {:error, _reason} -> {:error, :storage_failure}
    end
  end
end
