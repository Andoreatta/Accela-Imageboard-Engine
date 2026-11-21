defmodule Bcrypt do
  @moduledoc """
  VENDORED STUB — see `vendor/bcrypt_elixir_stub/mix.exs`.

  This module only exists so that `ash_authentication` (which hard-depends on
  `bcrypt_elixir`) compiles on machines without an MSVC toolchain. Password
  hashing is performed by `AccelaImageboard.Auth.Pbkdf2HashProvider` using
  Erlang/OTP's `:crypto.pbkdf2_hmac/5`.

  Calling any function here is a programming error and will raise.
  """

  @stub_error """
  Bcrypt stub invoked!

  This project vendors bcrypt_elixir as an empty stub (no NIF compiler
  available on this machine). Password hashing goes through
  AccelaImageboard.Auth.Pbkdf2HashProvider instead.

  To restore real Bcrypt:
    1. Install the MSVC C++ Build Tools (or build on Linux/macOS)
    2. Remove the `{:bcrypt_elixir, path: "vendor/bcrypt_elixir_stub"}` line
       from the project's mix.exs
    3. Run `mix deps.unlock bcrypt_elixir && mix deps.get`
    4. Configure the password strategy's `hash_provider` back to
       AshAuthentication.BcryptProvider
  """

  def add_salt(_password, _options \\ []),
    do: raise(RuntimeError, @stub_error)

  def hash_pwd_salt(_password, _options \\ []),
    do: raise(RuntimeError, @stub_error)

  def check_pass(_user, _password, _options \\ []),
    do: raise(RuntimeError, @stub_error)

  def verify_pass(_password, _stored_hash),
    do: raise(RuntimeError, @stub_error)

  def no_user_verify(_options \\ []),
    do: raise(RuntimeError, @stub_error)
end

defmodule Bcrypt.Base64 do
  @moduledoc "See `Bcrypt` — vendored stub, never call."

  def encode64(_data, _options \\ []),
    do: raise(RuntimeError, "Bcrypt stub invoked — see Bcrypt module docs.")

  def decode64(_data),
    do: raise(RuntimeError, "Bcrypt stub invoked — see Bcrypt module docs.")
end
