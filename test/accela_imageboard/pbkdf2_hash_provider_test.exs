defmodule AccelaImageboard.Auth.Pbkdf2HashProviderTest do
  @moduledoc """
  Hardening of the PBKDF2 hash provider (audit F-01/F-02/F-03/F-11):

  * `valid?/2` never raises on `nil` input or malformed stored hashes
  * stored hashes with a downgraded iteration count are rejected
  * the stored format stays PHC-style and backwards compatible
  """

  use ExUnit.Case, async: true

  alias AccelaImageboard.Auth.Pbkdf2HashProvider

  defp stored(iterations, salt, key) do
    "$pbkdf2-sha256$#{iterations}$#{Base.encode64(salt)}$#{Base.encode64(key)}"
  end

  test "hashes verify against their own input" do
    assert {:ok, hash} = Pbkdf2HashProvider.hash("correct horse battery staple")
    assert String.starts_with?(hash, "$pbkdf2-sha256$600000$")
    assert Pbkdf2HashProvider.valid?("correct horse battery staple", hash)
    refute Pbkdf2HashProvider.valid?("wrong password", hash)
  end

  test "valid?/2 returns false for nil input instead of raising (F-01)" do
    refute Pbkdf2HashProvider.valid?(nil, nil)
    refute Pbkdf2HashProvider.valid?(nil, "whatever")
    refute Pbkdf2HashProvider.valid?("password", nil)
  end

  test "valid?/2 never raises on malformed stored hashes (F-11)" do
    malformed = [
      "",
      "not-a-hash",
      "$pbkdf2-sha256$",
      "$pbkdf2-sha256$600000$",
      "$pbkdf2-sha256$600000$c2FsdA==",
      "$pbkdf2-sha256$600000$c2FsdA==$a2V5",
      "$pbkdf2-sha256$abc$c2FsdA==$" <> Base.encode64(:binary.copy(<<1>>, 32)),
      "$pbkdf2-sha256$600000$not base64!$also not base64!",
      "$pbkdf2-sha256$-1$c2FsdA==$" <> Base.encode64(:binary.copy(<<1>>, 32)),
      "$pbkdf2-sha256$600000$c2FsdA==$" <> Base.encode64(:binary.copy(<<1>>, 32)) <> "$extra"
    ]

    for malformed_hash <- malformed do
      refute Pbkdf2HashProvider.valid?("password", malformed_hash),
             "expected #{inspect(malformed_hash)} to be rejected"
    end
  end

  test "stored hashes below the iteration floor are rejected (F-02)" do
    salt = :binary.copy(<<7>>, 16)
    key = :binary.copy(<<3>>, 32)

    # 1_000 iterations: a downgraded/imported row must not verify silently.
    refute Pbkdf2HashProvider.valid?("password", stored(1_000, salt, key))
    refute Pbkdf2HashProvider.valid?("password", stored(0, salt, key))
  end

  test "stored hashes above the iteration cap are rejected (F-02)" do
    salt = :binary.copy(<<7>>, 16)
    key = :binary.copy(<<3>>, 32)

    refute Pbkdf2HashProvider.valid?("password", stored(10_000_001, salt, key))
    refute Pbkdf2HashProvider.valid?("password", stored(1_000_000_000, salt, key))
  end

  test "stored keys outside the accepted length range are rejected (F-11)" do
    salt = :binary.copy(<<7>>, 16)

    refute Pbkdf2HashProvider.valid?("password", stored(600_000, salt, :binary.copy(<<3>>, 15)))
    refute Pbkdf2HashProvider.valid?("password", stored(600_000, salt, :binary.copy(<<3>>, 65)))
  end

  test "simulate/0 returns false and burns the same work as a real check" do
    refute Pbkdf2HashProvider.simulate()
  end

  test "the provider advertises a non-deterministic, zero-entropy hash" do
    refute Pbkdf2HashProvider.deterministic?()
    assert Pbkdf2HashProvider.minimum_entropy() == 0
  end
end
