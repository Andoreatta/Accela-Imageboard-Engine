defmodule AccelaImageboard.Secrets do
  @moduledoc """
  Runtime secrets provider for AshAuthentication token signing
  (reads env/OTP config, never compile-time).
  """

  use AshAuthentication.Secret

  @doc """
  Returns the token signing secret from OTP config (`:token_signing_secret`).
  """
  def secret_for(
        [:authentication, :tokens, :signing_secret],
        AccelaImageboard.Accounts.User,
        _opts,
        _context
      ) do
    Application.fetch_env(:accela_imageboard, :token_signing_secret)
  end
end
