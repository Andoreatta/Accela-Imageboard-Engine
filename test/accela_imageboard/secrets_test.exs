defmodule AccelaImageboard.SecretsTest do
  @moduledoc """
  Token signing secrets must never be empty (audit F-05): an empty
  `:token_signing_secret` would silently sign every JWT with `""`.
  """

  use ExUnit.Case, async: false

  alias AccelaImageboard.Accounts.User
  alias AccelaImageboard.Secrets

  @path [:authentication, :tokens, :signing_secret]

  defp secret, do: Secrets.secret_for(@path, User, [], %{})

  test "returns the configured signing secret" do
    assert {:ok, secret} = secret()
    assert is_binary(secret)
    assert byte_size(secret) > 0
  end

  test "rejects an empty signing secret" do
    previous = Application.get_env(:accela_imageboard, :token_signing_secret)
    on_exit(fn -> Application.put_env(:accela_imageboard, :token_signing_secret, previous) end)

    Application.put_env(:accela_imageboard, :token_signing_secret, "")
    assert secret() == :error
  end

  test "rejects a missing signing secret" do
    previous = Application.get_env(:accela_imageboard, :token_signing_secret)
    on_exit(fn -> Application.put_env(:accela_imageboard, :token_signing_secret, previous) end)

    Application.delete_env(:accela_imageboard, :token_signing_secret)
    assert secret() == :error
  end

  test "rejects a non-binary signing secret" do
    previous = Application.get_env(:accela_imageboard, :token_signing_secret)
    on_exit(fn -> Application.put_env(:accela_imageboard, :token_signing_secret, previous) end)

    Application.put_env(:accela_imageboard, :token_signing_secret, nil)
    assert secret() == :error
  end
end
