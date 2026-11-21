defmodule AccelaImageboardWeb.Plugs.RequestContext do
  @moduledoc """
  Computes the anonymous poster identity for the request and stores it where
  the Ash layer can read it.

  Identity = `AccelaImageboard.Security.IpHash.hash/1` of the client IP.
  Raw IPs are never persisted; the hash is a keyed HMAC (server secret),
  stable per client, impossible to reverse without the secret.

  ## Proxy handling

  `X-Forwarded-For` is honoured **only** when `conn.remote_ip` itself is one of
  the proxies listed in

      config :accela_imageboard, :trusted_proxies, ["10.0.0.0/8", "2001:db8::/32"]

  (plain IPs and CIDR blocks are accepted). When it is honoured, the header is
  walked from **right to left** and every hop that is itself a trusted proxy is
  skipped, so a client that prepends forged entries to the header cannot win:
  only the first hop the chain actually proves is used.

  Anything hostile degrades to `conn.remote_ip` instead of raising: empty,
  unparsable, port-suffixed or IPv4-mapped entries are normalised or ignored.

  The result is exposed as `conn.private[:accela_ip_hash]` only — never as an
  assign, so a template cannot leak the poster hash by accident.
  """

  @behaviour Plug

  import Bitwise, only: [bsl: 2, bsr: 2]
  import Plug.Conn, only: [get_req_header: 2, put_private: 3]

  @ipv4_bits 32
  @ipv6_bits 128

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    ip_hash = conn |> client_ip() |> AccelaImageboard.Security.IpHash.hash()
    put_private(conn, :accela_ip_hash, ip_hash)
  end

  defp client_ip(conn) do
    trusted = trusted_proxies()

    if trusted_proxy?(normalize(conn.remote_ip), trusted) do
      conn
      |> forwarded_chain()
      |> pick_client(trusted, conn.remote_ip)
    else
      normalize(conn.remote_ip)
    end
  end

  # `X-Forwarded-For` arrives as zero or more headers, each holding a comma
  # separated list. Entries that do not parse as an address are dropped: they
  # cannot identify a client and must never crash the request.
  defp forwarded_chain(conn) do
    conn
    |> get_req_header("x-forwarded-for")
    |> Enum.flat_map(&String.split(&1, ","))
    |> Enum.map(&parse_address/1)
    |> Enum.reject(&is_nil/1)
  end

  # Right to left: the first hop that is not one of *our* proxies is the only
  # address the chain proves. If the header is empty, or every hop is a trusted
  # proxy (so nothing in it proves anything), fall back to `conn.remote_ip`.
  defp pick_client([], _trusted, fallback), do: normalize(fallback)

  defp pick_client(chain, trusted, fallback) do
    chain
    |> Enum.reverse()
    |> Enum.find(normalize(fallback), &(not trusted_proxy?(&1, trusted)))
  end

  ## trusted proxy configuration

  defp trusted_proxies do
    :accela_imageboard
    |> Application.get_env(:trusted_proxies, [])
    |> List.wrap()
    |> Enum.map(&parse_network/1)
    |> Enum.reject(&is_nil/1)
  end

  defp parse_network(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.split("/", parts: 2)
    |> network_from_parts()
  end

  defp parse_network(ip) when is_tuple(ip) and tuple_size(ip) in [4, 8],
    do: {ip, address_bits(ip)}

  defp parse_network(_value), do: nil

  defp network_from_parts([address]) do
    case parse_address(address) do
      nil -> nil
      ip -> {ip, address_bits(ip)}
    end
  end

  defp network_from_parts([address, prefix]) do
    with ip when not is_nil(ip) <- parse_address(address),
         {prefix, ""} <- Integer.parse(prefix),
         true <- prefix >= 0 and prefix <= address_bits(ip) do
      {ip, prefix}
    else
      _invalid -> nil
    end
  end

  defp trusted_proxy?(ip, trusted), do: Enum.any?(trusted, &in_network?(ip, &1))

  defp in_network?(ip, {network, prefix}) do
    tuple_size(ip) == tuple_size(network) and
      prefix_matches?(ip_to_int(ip), ip_to_int(network), address_bits(ip) - prefix)
  end

  defp prefix_matches?(ip, network, shift), do: bsr(ip, shift) == bsr(network, shift)

  defp ip_to_int(ip) do
    ip
    |> Tuple.to_list()
    |> Enum.reduce(0, fn part, acc -> bsl(acc, part_bits(ip)) + part end)
  end

  defp part_bits(ip) when tuple_size(ip) == 4, do: 8
  defp part_bits(_ip), do: 16

  defp address_bits(ip) when tuple_size(ip) == 4, do: @ipv4_bits
  defp address_bits(_ip), do: @ipv6_bits

  ## address parsing

  defp parse_address(entry) when is_binary(entry) do
    entry
    |> String.trim()
    |> strip_brackets_and_port()
    |> to_ip()
  end

  defp parse_address(_entry), do: nil

  defp to_ip(""), do: nil

  defp to_ip(entry) do
    case :inet.parse_address(String.to_charlist(entry)) do
      {:ok, ip} -> normalize(ip)
      {:error, _reason} -> nil
    end
  end

  # `[2001:db8::1]:443`, `[2001:db8::1]` and `203.0.113.7:53121` are all valid
  # in the wild; an unbracketed IPv6 address keeps its colons untouched.
  defp strip_brackets_and_port("[" <> rest), do: rest |> String.split("]") |> hd()

  defp strip_brackets_and_port(entry) do
    case String.split(entry, ":") do
      [address, port] -> if digits?(port), do: address, else: entry
      _all_colons -> entry
    end
  end

  defp digits?(""), do: false

  defp digits?(value) do
    case Integer.parse(value) do
      {_number, ""} -> true
      _not_a_number -> false
    end
  end

  # Dual-stack sockets report IPv4 clients as `::ffff:1.2.3.4`; folding it onto
  # the IPv4 form keeps one poster identity per client across both stacks.
  defp normalize({0, 0, 0, 0, 0, 0xFFFF, high, low}) do
    {div(high, 256), rem(high, 256), div(low, 256), rem(low, 256)}
  end

  defp normalize(ip), do: ip
end
