defmodule AccelaImageboard.Secrets do
  @moduledoc """
  Runtime secrets provider for AshAuthentication token signing
  (reads env/OTP config, never compile-time).

  A secret is only returned when it is a **non-empty binary**: an empty
  `:token_signing_secret` would silently sign every JWT with `""`, so it is
  rejected and the authentication flow fails closed instead (audit F-05).
  """

  use AshAuthentication.Secret

  @doc """
  Returns the token signing secret from OTP config (`:token_signing_secret`).

  Returns `:error` when the secret is missing, `nil` or an empty binary.
  """
  def secret_for(
        [:authentication, :tokens, :signing_secret],
        AccelaImageboard.Accounts.User,
        _opts,
        _context
      ) do
    case Application.fetch_env(:accela_imageboard, :token_signing_secret) do
      {:ok, secret} when is_binary(secret) and byte_size(secret) > 0 -> {:ok, secret}
      _missing_or_empty -> :error
    end
  end
end
