defmodule AccelaImageboard.Security.IpHash do
  @moduledoc """
  Deterministic, keyed hashing of client IPs for anonymous identity.

  Imageboards need a stable per-poster identity without storing raw IPs.
  We store an HMAC-SHA256 of the client IP peppered with a server-side
  secret, so:

  * the same IP always maps to the same "poster hash" (tripcode-like UX);
  * the original IP cannot be recovered without the secret;
  * rotating the secret invalidates all poster hashes (acceptable in prod,
    rotate only on leak).

  Input is normalized before hashing so that *representation* can never be
  used to evade a ban or a rate limit (audit F-09): IPv4-mapped IPv6
  addresses (`::ffff:a.b.c.d`) hash like the plain IPv4 address, zone
  identifiers (`fe80::1%eth0`) are dropped, and the address is re-rendered
  in the canonical compressed lowercase form that `:inet.ntoa/1` produces.

  The pepper comes from config and MUST come from `SECRET_KEY_BASE` or a
  dedicated `IP_HASH_SECRET` env var in production.
  """

  @algo :sha256

  @doc """
  Hashes an IP (tuple or binary form) into a hex digest using HMAC.
  """
  @spec hash(:inet.ip_address() | String.t()) :: String.t()
  def hash(ip) when is_binary(ip) do
    ip |> normalize() |> hmac()
  end

  def hash(ip) when is_tuple(ip) do
    ip |> :inet.ntoa() |> to_string() |> hash()
  end

  def hash(_), do: raise(ArgumentError, "expected an IP tuple or binary, got invalid input")

  @doc """
  Verifies a candidate IP against a stored hash (constant-time).
  """
  @spec verify?(String.t(), :inet.ip_address() | String.t()) :: boolean()
  def verify?(stored_hash, ip) when is_binary(stored_hash) do
    Plug.Crypto.secure_compare(stored_hash, hash(ip))
  end

  defp hmac(normalized) do
    Base.encode16(:crypto.mac(:hmac, @algo, pepper(), normalized), case: :lower)
  end

  defp normalize(ip) do
    ip
    |> strip_zone_id()
    |> parse!()
    |> unmap_ipv4()
    |> :inet.ntoa()
    |> to_string()
  end

  # `fe80::1%eth0` (and its URL-encoded form `%25eth0`) carries a local zone
  # hint, not part of the address: drop it so both spellings agree.
  defp strip_zone_id(ip) do
    ip
    |> String.split("%", parts: 2)
    |> hd()
  end

  defp parse!(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, parsed} -> parsed
      {:error, _reason} -> raise ArgumentError, "invalid IP: #{inspect(ip)}"
    end
  end

  # `::ffff:a.b.c.d` is the same client as `a.b.c.d`; collapsing it keeps one
  # hash per client instead of one per notation.
  defp unmap_ipv4({0, 0, 0, 0, 0, 0xFFFF, ab, cd}) do
    {div(ab, 256), rem(ab, 256), div(cd, 256), rem(cd, 256)}
  end

  defp unmap_ipv4(tuple), do: tuple

  defp pepper do
    Application.get_env(:accela_imageboard, __MODULE__)[:secret] ||
      Application.get_env(:accela_imageboard, AccelaImageboardWeb.Endpoint)[:secret_key_base] ||
      raise("""
      No secret available for IP hashing.

      Configure in config/runtime.exs:

          config :accela_imageboard, AccelaImageboard.Security.IpHash,
            secret: System.fetch_env!(\"IP_HASH_SECRET\")
      """)
  end
end
