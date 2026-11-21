defmodule AccelaImageboardWeb.MediaValidationTest do
  @moduledoc """
  The upload path decides what a file is from its bytes, never from what the client
  claims.

  These tests cover the validator (magic bytes, hostile payloads, size bounds) and
  the storage layer (roundtrip, opaque keys, traversal refusal, delete).
  """

  use ExUnit.Case, async: true

  alias AccelaImageboard.Media.Storage
  alias AccelaImageboard.Media.Validation
  alias AccelaImageboardWeb.BoardCase

  describe "magic-byte validation" do
    test "accepts the four supported image formats" do
      assert {:ok, %{content_type: "image/png", extension: "png"}} =
               Validation.validate(BoardCase.temp_file(BoardCase.png(), "a.png"), "image/png")

      assert {:ok, %{content_type: "image/jpeg", extension: "jpg"}} =
               Validation.validate(BoardCase.temp_file(BoardCase.jpeg(), "a.jpg"), "image/jpeg")

      assert {:ok, %{content_type: "image/gif", extension: "gif"}} =
               Validation.validate(BoardCase.temp_file(BoardCase.gif(), "a.gif"), "image/gif")

      assert {:ok, %{content_type: "image/webp", extension: "webp"}} =
               Validation.validate(BoardCase.temp_file(BoardCase.webp(), "a.webp"), "image/webp")
    end

    test "accepts a file whose bytes decide the type when the client sends no type" do
      path = BoardCase.temp_file(BoardCase.png(), "no-type")

      assert {:ok, %{content_type: "image/png"}} = Validation.validate(path, nil)

      assert {:ok, %{content_type: "image/png"}} =
               Validation.validate(path, "application/octet-stream")
    end

    test "rejects an SVG, which is markup in the board's origin" do
      path = BoardCase.temp_file(BoardCase.svg(), "evil.svg")
      assert {:error, :unsupported_type} = Validation.validate(path, "image/svg+xml")
    end

    test "rejects a renamed text file that claims to be a JPEG" do
      path = BoardCase.temp_file(BoardCase.fake_jpeg(), "evil.jpg")
      assert {:error, :unsupported_type} = Validation.validate(path, "image/jpeg")
    end

    test "rejects a valid signature whose declared type disagrees" do
      path = BoardCase.temp_file(BoardCase.png(), "a.png")
      assert {:error, :content_type_mismatch} = Validation.validate(path, "image/gif")
    end

    test "rejects a GIF/HTML polyglot even though its signature is valid" do
      path = BoardCase.temp_file(BoardCase.gif_html_polyglot(), "polyglot.gif")
      assert {:error, :suspicious_content} = Validation.validate(path, "image/gif")
    end

    test "rejects empty, tiny and oversized files" do
      assert {:error, :empty_file} = Validation.validate(BoardCase.temp_file("", "empty"), nil)

      assert {:error, :too_small} =
               Validation.validate(BoardCase.temp_file("GIF89a", "tiny.gif"), nil)

      # 11 MiB of PNG: rejected on stat, before any of it is read.
      oversized = BoardCase.png() <> :binary.copy(<<0>>, Validation.limits().max_bytes)

      assert {:error, :too_large} =
               Validation.validate(BoardCase.temp_file(oversized, "huge.png"), "image/png")
    end

    test "rejects a missing file instead of crashing" do
      assert {:error, :unreadable_file} =
               Validation.validate("/definitely/not/here.png", "image/png")
    end
  end

  describe "limits" do
    test "come from config with sane defaults" do
      limits = Validation.limits()
      assert limits.max_bytes > 0
      assert limits.min_bytes > 0
      assert limits.max_bytes >= limits.min_bytes
      assert Validation.content_types() == ~w(image/jpeg image/png image/gif image/webp)
      assert ".png" in Validation.extensions()
    end
  end

  describe "storage" do
    test "stores a file under an opaque key and reads it back unchanged" do
      dir = BoardCase.use_temporary_uploads_dir()
      source = BoardCase.temp_file(BoardCase.png(), "a.png")

      assert {:ok, stored} =
               Storage.store(source, %{extension: "png", content_type: "image/png"}, "a.png")

      assert Storage.valid_key?(stored.storage_key)
      assert stored.content_type == "image/png"
      assert stored.original_filename == "a.png"
      assert stored.sha256 == Base.encode16(:crypto.hash(:sha256, BoardCase.png()), case: :lower)
      assert byte_size(BoardCase.png()) == stored.byte_size

      stored_path = Path.join(dir, stored.storage_key)
      assert File.exists?(stored_path)
      assert File.read!(stored_path) == BoardCase.png()

      assert {:ok, read_path} = Storage.read(stored.storage_key)
      assert File.read!(read_path) == BoardCase.png()

      assert :ok = Storage.delete(stored.storage_key)
      refute File.exists?(stored_path)
    end

    test "refuses keys that are not its own, so a traversal cannot escape the root" do
      BoardCase.use_temporary_uploads_dir()

      for key <- [
            "../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "/etc/passwd",
            "0123456789abcdef0123456789abcdef/../../x.png",
            "not-a-key.png",
            "",
            nil
          ] do
        refute Storage.valid_key?(key)
        assert {:error, :not_found} = Storage.read(key)
        assert {:error, :invalid_key} = Storage.path(key)
      end
    end

    test "reports a missing file as not found" do
      BoardCase.use_temporary_uploads_dir()
      assert {:error, :not_found} = Storage.read("0123456789abcdef0123456789abcdef.png")
    end

    test "root defaults to ./uploads when no config is set" do
      previous = Application.get_env(:accela_imageboard, :uploads_dir)
      Application.delete_env(:accela_imageboard, :uploads_dir)

      on_exit(fn ->
        if previous, do: Application.put_env(:accela_imageboard, :uploads_dir, previous)
      end)

      assert Storage.root() == Path.join(File.cwd!(), "uploads")
    end
  end
end
