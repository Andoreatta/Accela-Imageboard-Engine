defmodule AccelaImageboard.Security.TokenHash do
  @moduledoc """
  Server-issued anonymous session tokens, hashed so the token itself is never
  stored.

  The exact IP hash (`AccelaImageboard.Security.IpHash.hash/1`) and the network
  prefix hash (`net/1`) both describe where a poster comes from, so a poster who
  both rotates the IP *and* leaves the block (mobile data, Tor) still evades a
  ban. The third identifier closes that gap from the other side: the server
  mints a random token, keeps it in the visitor's cookie, and stores only its
  keyed HMAC on the content the visitor creates. A `:token`-scoped ban then
  follows the visitor's cookie wherever the address moves to.

  Properties:

  * `generate/0` returns 32 bytes of CSPRNG entropy, URL-safe (`Base.url_encode64/2`
    without padding), so it can live in a cookie as-is;
  * `hash/1` is HMAC-SHA256 with the same pepper as `IpHash` and a different
    message domain (`"anon-token:"`), so a token hash can never collide with an
    IP hash — an address cannot be made to inherit somebody else's token
    identity, nor the reverse;
  * `valid?/2` compares in constant time and fails closed on `nil` or any
    non-binary input;
  * `hash/1` refuses empty or non-binary tokens with `ArgumentError`: an empty
    token would be a single shared identity for everybody who lacks one.

  Like `IpHash`, all of this is server-side: tokens and hashes come from the
  connection, never from request parameters.
  """

  @algo :sha256
  @token_bytes 32
  @domain "anon-token:"

  @doc """
  Generates a fresh anonymous session token (32 bytes, URL-safe, unpadded).
  """
  @spec generate() :: String.t()
  def generate do
    @token_bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Hashes a token into a 64-character lowercase hex digest using HMAC-SHA256.

  Raises `ArgumentError` for `nil`, non-binary or empty tokens.
  """
  @spec hash(String.t()) :: String.t()
  def hash(token) when is_binary(token) and byte_size(token) > 0 do
    Base.encode16(:crypto.mac(:hmac, @algo, pepper(), @domain <> token), case: :lower)
  end

  def hash(_token), do: raise(ArgumentError, "expected a non-empty binary token")

  @doc """
  Checks a candidate token against a stored token hash, in constant time.

  Returns `false` for a `nil`/non-binary stored hash or token, and for any
  mismatch — it never raises.
  """
  @spec valid?(String.t() | nil, String.t() | nil) :: boolean()
  def valid?(stored_hash, token)
      when is_binary(stored_hash) and is_binary(token) and byte_size(token) > 0 and
             byte_size(stored_hash) > 0 do
    Plug.Crypto.secure_compare(stored_hash, hash(token))
  end

  def valid?(_stored_hash, _token), do: false

  # Same pepper and the same fallback chain as `IpHash`: one secret to rotate,
  # one place where it is documented (see `config/runtime.exs`).
  defp pepper do
    Application.get_env(:accela_imageboard, AccelaImageboard.Security.IpHash)[:secret] ||
      Application.get_env(:accela_imageboard, AccelaImageboardWeb.Endpoint)[:secret_key_base] ||
      raise("""
      No secret available for token hashing.

      Configure in config/runtime.exs:

          config :accela_imageboard, AccelaImageboard.Security.IpHash,
            secret: System.fetch_env!("IP_HASH_SECRET")
      """)
  end
end
