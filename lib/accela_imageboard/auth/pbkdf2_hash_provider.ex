defmodule AccelaImageboard.Auth.Pbkdf2HashProvider do
  @moduledoc """
  `AshAuthentication.HashProvider` implementation backed by Erlang/OTP's
  PBKDF2 (`:crypto.pbkdf2_hmac/5`), which uses the system's audited OpenSSL.

  Rationale: this machine has no MSVC toolchain, so NIF-based hashers
  (bcrypt_elixir/argon2_elixir) cannot compile. PBKDF2-HMAC-SHA256 with
  600_000 iterations is an OWASP-approved password hash (same magnitude as
  Django/passlib defaults) and requires zero native dependencies.

  Hashes are stored in a PHC-style string:

      $pbkdf2-sha256$iterations$<b64 salt>$<b64 derived key>
  """

  @behaviour AshAuthentication.HashProvider

  @iterations 600_000
  @salt_bytes 16
  @key_len 32
  @digest :sha256

  @impl AshAuthentication.HashProvider
  def hash(input) when is_binary(input) do
    salt = :crypto.strong_rand_bytes(@salt_bytes)

    derived =
      :crypto.pbkdf2_hmac(@digest, input, salt, @iterations, @key_len)

    {:ok, encode(salt, derived)}
  rescue
    _ -> :error
  end

  # Hash with action context — same semantics as hash/1.
  @impl AshAuthentication.HashProvider
  def hash(input, _context) when is_binary(input), do: hash(input)

  @impl AshAuthentication.HashProvider
  def valid?(input, stored) when is_binary(input) and is_binary(stored) do
    case decode(stored) do
      {:ok, iterations, salt, expected} ->
        candidate = :crypto.pbkdf2_hmac(@digest, input, salt, iterations, byte_size(expected))
        Plug.Crypto.secure_compare(candidate, expected)

      :error ->
        false
    end
  end

  # Fills roughly the same amount of time as a real check to blunt timing
  # attacks on user enumeration.
  @impl AshAuthentication.HashProvider
  def simulate do
    hash("simulated-password-to-burn-cpu")
    false
  end

  # PBKDF2 is computationally expensive, so low-entropy inputs are still
  # impractical to brute force — same argument as bcrypt.
  @impl AshAuthentication.HashProvider
  def minimum_entropy, do: 0

  # Random salt per hash → non-deterministic.
  @impl AshAuthentication.HashProvider
  def deterministic?, do: false

  defp encode(salt, derived) do
    "$pbkdf2-sha256$#{@iterations}$#{Base.encode64(salt)}$#{Base.encode64(derived)}"
  end

  defp decode("$pbkdf2-sha256$" <> rest) do
    with [iter, salt, key] <- String.split(rest, "$"),
         {iterations, ""} <- Integer.parse(iter),
         {:ok, salt} <- Base.decode64(salt),
         {:ok, key} <- Base.decode64(key),
         true <- iterations > 0 and iterations <= 10_000_000,
         true <- byte_size(salt) >= 8 and byte_size(key) >= 16 do
      {:ok, iterations, salt, key}
    else
      _ -> :error
    end
  end

  defp decode(_), do: :error
end
