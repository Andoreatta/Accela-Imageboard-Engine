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

  Decoding is defensive by design (audit F-01/F-02/F-03/F-11):

  * `valid?/2` returns `false` — never raises — for `nil` inputs and for
    malformed, truncated or downgraded stored hashes, so a missing password
    or a corrupted row is an authentication failure, not a 500.
  * The iteration count is re-read from the stored string, so it is clamped
    to a sane floor and ceiling; a row written with a downgraded cost is
    rejected instead of silently verifying.
  """

  @behaviour AshAuthentication.HashProvider

  require Logger

  @iterations 600_000
  @salt_bytes 16
  @key_len 32
  @digest :sha256

  # Accepted range for iterations read back from a stored hash. The floor is
  # ~1/6 of the current cost (rejecting downgraded/imported rows), the ceiling
  # bounds the work an attacker who can write a hash row could force.
  @min_iterations 100_000
  @max_iterations 10_000_000
  @min_key_bytes 16
  @max_key_bytes 64

  @impl AshAuthentication.HashProvider
  def hash(input) when is_binary(input) do
    salt = :crypto.strong_rand_bytes(@salt_bytes)

    derived =
      :crypto.pbkdf2_hmac(@digest, input, salt, @iterations, @key_len)

    {:ok, encode(salt, derived)}
  rescue
    # Narrowed on purpose (audit F-03): the `HashProvider` contract returns
    # `:error` instead of raising, and the only realistic failures here are
    # `:crypto`'s `:badarg` (an unusable OpenSSL/provider) or an invalid
    # argument (an empty/oversized input). Anything else — exits, throws,
    # unexpected errors in encoding — must not be swallowed as a silent
    # "cannot hash" that callers would misread as a wrong password.
    error in [ArgumentError, ErlangError] ->
      Logger.error("PBKDF2 hashing failed: #{Exception.message(error)}")
      :error
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

  # No password set / field not selected: fail closed without burning CPU
  # twice, but keep the timing cost of a real verification (F-01).
  def valid?(nil, _stored), do: simulate()
  def valid?(_input, nil), do: simulate()

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
         true <- iterations >= @min_iterations and iterations <= @max_iterations,
         true <- byte_size(salt) >= 8,
         true <- byte_size(key) >= @min_key_bytes and byte_size(key) <= @max_key_bytes do
      {:ok, iterations, salt, key}
    else
      _ -> :error
    end
  end

  defp decode(_), do: :error
end
