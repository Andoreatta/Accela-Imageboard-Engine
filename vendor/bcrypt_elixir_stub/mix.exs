defmodule BcryptElixirStub.MixProject do
  use Mix.Project

  @version "3.3.2"
  @description """
  LOCAL VENDORED STUB of bcrypt_elixir. Not a real implementation.

  ash_authentication declares bcrypt_elixir as a hard dependency, but this
  project compiles password hashes with pure-OTP PBKDF2-HMAC-SHA256
  (see AccelaImageboard.Auth.Pbkdf2HashProvider). To keep `mix deps` free of
  NIF/native compilation requirements on MSVC-less Windows machines, we satisfy
  the dependency graph with this stub. Every function raises with a clear error
  so it can never be used silently.

  If you install MSVC Build Tools (or move to Linux/macOS), remove this path
  dependency and the real `bcrypt_elixir` from Hex will be used again.
  """

  def project do
    [
      app: :bcrypt_elixir,
      version: @version,
      description: @description,
      elixir: "~> 1.17",
      deps: []
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end
end
