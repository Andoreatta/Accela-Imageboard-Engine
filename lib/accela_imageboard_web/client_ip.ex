defmodule AccelaImageboardWeb.ClientIp do
  @moduledoc """
  The single source of truth for "which client is this", for both HTTP requests and
  LiveView connections.

  An imageboard's anti-abuse design rests on a small set of keyed hashes of the
  poster, none of which is ever stored in raw form:

    * `ip_hash` - the exact address (the historic identifier);
    * `net_hash`/`net_scope` - the network prefix (`/24` for IPv4, `/64` for IPv6),
      which survives a client rotating the low bits of its address;
    * `token_hash` - the hash of a server-issued anonymous session token (see
      `token_hash/1`), which survives neither cookies being cleared nor a proxy
      hiding the address but is stable while the browser keeps its session.

  HTTP requests get them from `AccelaImageboardWeb.Plugs.RequestContext`; LiveView
  post/thread creation gets them from the socket peer data and session at mount
  (`Phoenix.LiveView.get_connect_info/2`). Both go through this module so the two
  paths can never disagree about a poster.

  ## Proxy handling

  `X-Forwarded-For` is honoured **only** when the peer address itself is one of the
  proxies listed in

      config :accela_imageboard, :trusted_proxies, ["10.0.0.0/8", "2001:db8::/32"]

  (plain IPs and CIDR blocks are accepted). When it is honoured, the header is
  walked from **right to left** and every hop that is itself a trusted proxy is
  skipped, so a client that prepends forged entries to the header cannot win: only
  the first hop the chain actually proves is used.

  Anything hostile degrades to the peer address instead of raising: empty,
  unparsable, port-suffixed or IPv4-mapped entries are normalised or ignored.
  """

  import Bitwise, only: [bsl: 2, bsr: 2]

  alias AccelaImageboard.Security.IpHash
  alias AccelaImageboard.Security.TokenHash

  @ipv4_bits 32
  @ipv6_bits 128

  @forwarded_header "x-forwarded-for"

  @doc """
  Keyed poster hash for a peer address and its request headers.

  Returns `nil` when no peer address is available (the caller then refuses to
  attribute the action instead of inventing an identity).
  """
  @spec hash(:inet.ip_address() | nil, [{String.t(), String.t()}]) :: String.t() | nil
  def hash(nil, _headers), do: nil

  def hash(remote_ip, headers) when is_tuple(remote_ip) do
    remote_ip
    |> resolve(normalize_headers(headers))
    |> IpHash.hash()
  end

  @doc """
  Keyed poster hash for a `Plug.Conn` (used by the request-context plug).
  """
  @spec from_conn(Plug.Conn.t()) :: String.t() | nil
  def from_conn(%Plug.Conn{} = conn), do: hash(conn.remote_ip, conn.req_headers)

  @typedoc """
  The address-derived identifiers a ban can match.

  `ip_hash` is the exact-address hash (the historic identifier), `net_scope` names
  the prefix length that was hashed (`:ipv4_24` or `:ipv6_64`) and `net_hash` is the
  hash of that prefix. Rotating the last address octets - or the IPv6 host suffix -
  changes `ip_hash` but not `net_hash`, which is what makes a ban survive cheap
  evasion. All of them are keyed HMACs: no raw address is ever stored.
  """
  @type identity :: %{
          ip_hash: String.t(),
          net_scope: :ipv4_24 | :ipv6_64,
          net_hash: String.t()
        }

  @doc """
  Full anonymous identity (exact hash plus network prefix) for a peer and headers.

  Uses exactly the same resolution as `hash/2`: a forwarded header is believed only
  when the peer is a configured trusted proxy, and the same right-to-left walk picks
  the client, so the two identifiers can never describe different clients. Returns
  `nil` when there is no peer address at all.
  """
  @spec identity(:inet.ip_address() | nil, [{String.t(), String.t()}]) :: identity() | nil
  def identity(nil, _headers), do: nil

  def identity(remote_ip, headers) when is_tuple(remote_ip) do
    client = resolve(remote_ip, normalize_headers(headers))
    {net_scope, net_hash} = IpHash.net(client)

    %{ip_hash: IpHash.hash(client), net_scope: net_scope, net_hash: net_hash}
  end

  @doc """
  Full anonymous identity for a `Plug.Conn`.
  """
  @spec identity_from_conn(Plug.Conn.t()) :: identity() | nil
  def identity_from_conn(%Plug.Conn{} = conn), do: identity(conn.remote_ip, conn.req_headers)

  @doc """
  Keyed hash of the anonymous session token, or `nil` when there is no usable token.

  The raw token lives only in the signed session cookie and in `conn.private`; the
  domain stores this hash, so presenting the same token again is recognised without
  the server ever persisting the token itself.
  """
  @spec token_hash(binary() | nil) :: String.t() | nil
  def token_hash(token) when is_binary(token) and byte_size(token) > 0, do: TokenHash.hash(token)
  def token_hash(_no_token), do: nil

  @doc """
  Ash action context carrying the whole anonymous identity (contract v2).

  Takes the address identity (`identity/2`) and the token hash (`token_hash/1`) and
  returns `%{anonymous: %{ip_hash: ..., net_scope: ..., net_hash: ..., token_hash: ...}}`
  with absent values dropped, or `%{}` when neither is available - the domain then
  refuses to attribute the action instead of inventing an identity.

  Only server-side facts are ever passed in here: the peer address, the trusted-proxy
  resolution and the session token. Nothing in this map can be supplied by a form.
  """
  @spec posting_context(identity() | nil, String.t() | nil) :: map()
  def posting_context(identity, token_hash) do
    anonymous =
      %{
        ip_hash: present(identity, :ip_hash),
        net_scope: present(identity, :net_scope),
        net_hash: present(identity, :net_hash),
        token_hash: token_hash
      }
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    if anonymous == %{}, do: %{}, else: %{anonymous: anonymous}
  end

  defp present(nil, _key), do: nil
  defp present(identity, key) when is_map(identity), do: Map.get(identity, key)

  @doc """
  Ash action context that carries the anonymous poster identity.

  Domain changes such as `AccelaImageboard.Boards.Changes.SetPosterHash` read it from
  `changeset.context[:anonymous][:ip_hash]`, so the value can only ever come from
  the server. When no peer address is available the context is empty and the domain
  refuses to attribute the action, instead of inventing an identity.

  Kept for the address-only case; prefer `posting_context/2`, which also carries the
  network prefix and the session token.
  """
  @spec anonymous_context(String.t() | nil) :: map()
  def anonymous_context(nil), do: %{}
  def anonymous_context(ip_hash) when is_binary(ip_hash), do: %{anonymous: %{ip_hash: ip_hash}}

  ## resolution

  defp resolve(remote_ip, headers) do
    trusted = trusted_proxies()

    if trusted_proxy?(normalize(remote_ip), trusted) do
      headers
      |> forwarded_chain()
      |> pick_client(trusted, remote_ip)
    else
      normalize(remote_ip)
    end
  end

  defp normalize_headers(headers) when is_list(headers) do
    Enum.map(headers, fn
      {name, value} when is_binary(name) -> {String.downcase(name), value}
      _other -> {"", ""}
    end)
  end

  defp normalize_headers(_headers), do: []

  # `X-Forwarded-For` arrives as zero or more headers, each holding a comma
  # separated list. Entries that do not parse as an address are dropped: they
  # cannot identify a client and must never crash the request.
  defp forwarded_chain(headers) do
    headers
    |> Enum.filter(fn {name, _value} -> name == @forwarded_header end)
    |> Enum.map(fn {_name, value} -> value end)
    |> Enum.flat_map(&String.split(&1, ","))
    |> Enum.map(&parse_address/1)
    |> Enum.reject(&is_nil/1)
  end

  # Right to left: the first hop that is not one of *our* proxies is the only
  # address the chain proves. If the header is empty, or every hop is a trusted
  # proxy (so nothing in it proves anything), fall back to the peer address.
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
