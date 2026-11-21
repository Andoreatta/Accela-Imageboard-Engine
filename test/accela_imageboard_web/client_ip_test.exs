defmodule AccelaImageboardWeb.ClientIpTest do
  @moduledoc """
  The client identity is the hinge of anonymous moderation, so both entry points
  (HTTP plug and LiveView mount) are pinned here: which address is believed, when
  a forwarded header may be trusted, and what happens with hostile input.
  """

  use ExUnit.Case, async: false

  alias AccelaImageboard.Security.IpHash
  alias AccelaImageboard.Security.TokenHash
  alias AccelaImageboardWeb.ClientIp
  alias AccelaImageboardWeb.Plugs.RequestContext

  @peer {203, 0, 113, 9}
  @proxy {10, 1, 2, 3}
  @client {198, 51, 100, 7}

  setup do
    previous = Application.get_env(:accela_imageboard, :trusted_proxies)
    on_exit(fn -> restore_trusted_proxies(previous) end)
    :ok
  end

  defp restore_trusted_proxies(nil),
    do: Application.delete_env(:accela_imageboard, :trusted_proxies)

  defp restore_trusted_proxies(value),
    do: Application.put_env(:accela_imageboard, :trusted_proxies, value)

  defp trust(proxies), do: Application.put_env(:accela_imageboard, :trusted_proxies, proxies)

  defp conn_for(remote_ip, headers \\ []) do
    Enum.reduce(headers, %{Plug.Test.conn(:get, "/") | remote_ip: remote_ip}, fn {name, value},
                                                                                 conn ->
      Plug.Conn.put_req_header(conn, name, value)
    end)
  end

  describe "hash/2 without trusted proxies" do
    test "ignores a forwarded header entirely" do
      trust([])

      assert ClientIp.hash(@peer, [{"x-forwarded-for", "1.1.1.1"}]) == IpHash.hash(@peer)
    end

    test "ignores a forwarded header when the setting is absent" do
      Application.delete_env(:accela_imageboard, :trusted_proxies)

      assert ClientIp.hash(@peer, [{"x-forwarded-for", "1.1.1.1"}]) == IpHash.hash(@peer)
    end

    test "is stable for the same address and distinct across addresses" do
      assert ClientIp.hash(@peer, []) == ClientIp.hash(@peer, [])
      refute ClientIp.hash(@peer, []) == ClientIp.hash(@client, [])
    end
  end

  describe "hash/2 with trusted proxies" do
    test "is ignored when the peer itself is not a trusted proxy" do
      trust(["10.0.0.0/8"])

      assert ClientIp.hash(@peer, [{"x-forwarded-for", "1.1.1.1"}]) == IpHash.hash(@peer)
    end

    test "honours a single forwarded hop from a trusted peer" do
      trust(["10.0.0.0/8"])

      assert ClientIp.hash(@proxy, [{"x-forwarded-for", "198.51.100.7"}]) == IpHash.hash(@client)
    end

    test "ignores client-forged entries prepended to the header" do
      trust(["10.0.0.0/8"])

      headers = [{"x-forwarded-for", "1.1.1.1, 198.51.100.7"}]

      assert ClientIp.hash(@proxy, headers) == IpHash.hash(@client)
    end

    test "walks past hops that are themselves trusted proxies" do
      trust(["10.0.0.0/8"])

      headers = [{"x-forwarded-for", "1.1.1.1, 198.51.100.7, 10.9.9.9"}]

      assert ClientIp.hash(@proxy, headers) == IpHash.hash(@client)
    end

    test "accepts a plain address as a trusted entry" do
      trust(["10.1.2.3"])

      assert ClientIp.hash(@proxy, [{"x-forwarded-for", "198.51.100.7"}]) == IpHash.hash(@client)

      refute ClientIp.hash({10, 1, 2, 4}, [{"x-forwarded-for", "198.51.100.7"}]) ==
               IpHash.hash(@client)
    end

    test "accepts IPv6 CIDR blocks for dual-stack proxies" do
      trust(["::1/128"])

      headers = [{"x-forwarded-for", "198.51.100.7"}]
      local = {0, 0, 0, 0, 0, 0, 0, 1}

      assert ClientIp.hash(local, headers) == IpHash.hash(@client)
    end
  end

  describe "address parsing" do
    setup do
      trust(["10.0.0.0/8"])
      :ok
    end

    test "strips a port from an IPv4 hop" do
      assert ClientIp.hash(@proxy, [{"x-forwarded-for", "198.51.100.7:53121"}]) ==
               IpHash.hash(@client)
    end

    test "strips brackets and a port from an IPv6 hop" do
      headers = [{"x-forwarded-for", "[2001:db8::1]:443"}]

      assert ClientIp.hash(@proxy, headers) ==
               IpHash.hash({0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1})
    end

    test "folds IPv4-mapped addresses onto the IPv4 identity" do
      headers = [{"x-forwarded-for", "::ffff:198.51.100.7"}]

      assert ClientIp.hash(@proxy, headers) == IpHash.hash(@client)
    end

    test "folds an IPv4-mapped peer onto the IPv4 identity" do
      mapped = {0, 0, 0, 0, 0, 0xFFFF, 203 * 256, 113 * 256 + 9}

      assert ClientIp.hash(mapped, []) == IpHash.hash(@peer)
    end
  end

  describe "hostile or unusable input" do
    setup do
      trust(["10.0.0.0/8"])
      :ok
    end

    test "falls back to the peer for junk entries" do
      for header <- ["not-an-ip", "", " , ,", "999.1.1.1", "10.0.0.0/8", "<script>"] do
        assert ClientIp.hash(@proxy, [{"x-forwarded-for", header}]) == IpHash.hash(@proxy),
               "expected #{inspect(header)} to fall back to the peer"
      end
    end

    test "falls back to the peer when every hop is a trusted proxy" do
      assert ClientIp.hash(@proxy, [{"x-forwarded-for", "10.5.5.5"}]) == IpHash.hash(@proxy)
    end

    test "returns no identity for a missing peer address" do
      assert ClientIp.hash(nil, [{"x-forwarded-for", "198.51.100.7"}]) == nil
      assert ClientIp.anonymous_context(nil) == %{}
    end

    test "tolerates malformed header lists" do
      assert ClientIp.hash(@peer, :nonsense) == IpHash.hash(@peer)
      assert ClientIp.hash(@peer, [nil, :bad]) == IpHash.hash(@peer)
    end

    test "ignores other forwarding headers" do
      headers = [{"x-real-ip", "1.1.1.1"}, {"forwarded", "for=1.1.1.1"}]

      assert ClientIp.hash(@proxy, headers) == IpHash.hash(@proxy)
    end
  end

  describe "anonymous_context/1" do
    test "wraps the hash in the shape the domain changeset expects" do
      hash = ClientIp.hash(@peer, [])

      assert ClientIp.anonymous_context(hash) == %{anonymous: %{ip_hash: hash}}
    end
  end

  describe "RequestContext plug" do
    test "stores the poster hash in private, never in assigns" do
      trust([])

      conn = RequestContext.call(conn_for(@peer), [])

      assert conn.private[:accela_ip_hash] == IpHash.hash(@peer)
      assert conn.assigns == %{}
      refute Map.has_key?(conn.assigns, :accela_ip_hash)
    end

    test "uses the resolved client address behind a trusted proxy" do
      trust(["10.0.0.0/8"])

      conn = RequestContext.call(conn_for(@proxy, [{"x-forwarded-for", "198.51.100.7"}]), [])

      assert conn.private[:accela_ip_hash] == IpHash.hash(@client)
    end
  end

  describe "identity/2" do
    test "carries the exact hash and the IPv4 network prefix" do
      identity = ClientIp.identity(@peer, [])

      assert identity.ip_hash == IpHash.hash(@peer)
      assert identity.net_scope == :ipv4_24

      {scope, net_hash} = IpHash.net(@peer)
      assert scope == :ipv4_24
      assert identity.net_hash == net_hash
    end

    test "the prefix identity survives the last octet changing" do
      a = ClientIp.identity({203, 0, 113, 7}, [])
      b = ClientIp.identity({203, 0, 113, 200}, [])

      refute a.ip_hash == b.ip_hash
      assert a.net_scope == b.net_scope
      assert a.net_hash == b.net_hash
    end

    test "a different IPv4 /24 is a different identity" do
      a = ClientIp.identity({203, 0, 113, 7}, [])
      b = ClientIp.identity({203, 0, 114, 7}, [])

      refute a.net_hash == b.net_hash
    end

    test "an IPv6 peer is hashed at /64" do
      ipv6 = {0x2001, 0x0DB8, 0x0001, 0x0002, 0xDEAD, 0, 0, 1}
      identity = ClientIp.identity(ipv6, [])

      assert identity.ip_hash == IpHash.hash(ipv6)
      assert identity.net_scope == :ipv6_64
      assert {_scope, net_hash} = IpHash.net(ipv6)
      assert identity.net_hash == net_hash
    end

    test "an IPv4-mapped peer is identified as the plain IPv4 client" do
      mapped = {0, 0, 0, 0, 0, 0xFFFF, 203 * 256, 113 * 256 + 7}

      assert ClientIp.identity(mapped, []) == ClientIp.identity({203, 0, 113, 7}, [])
    end

    test "there is no identity without a peer address" do
      assert ClientIp.identity(nil, []) == nil
    end

    test "believes a forwarded header only for a trusted proxy, like hash/2" do
      trust(["10.0.0.0/8"])

      headers = [{"x-forwarded-for", "1.1.1.1, 198.51.100.7"}]

      assert ClientIp.identity(@proxy, headers) == ClientIp.identity(@client, [])
      assert ClientIp.identity(@peer, headers) == ClientIp.identity(@peer, [])
    end

    test "from a connection, it uses the peer and its headers" do
      trust([])

      assert ClientIp.identity_from_conn(conn_for(@peer)) == ClientIp.identity(@peer, [])
    end
  end

  describe "token_hash/1" do
    test "hashes a session token" do
      token = TokenHash.generate()

      hash = ClientIp.token_hash(token)

      assert hash == TokenHash.hash(token)
      assert hash =~ ~r/\A[0-9a-f]{64}\z/
    end

    test "is nil-safe" do
      assert ClientIp.token_hash(nil) == nil
      assert ClientIp.token_hash("") == nil
      assert ClientIp.token_hash(:not_a_token) == nil
    end

    test "two tokens hash differently" do
      refute ClientIp.token_hash(TokenHash.generate()) ==
               ClientIp.token_hash(TokenHash.generate())
    end
  end

  describe "posting_context/2" do
    test "carries the whole identity when both halves are present" do
      identity = ClientIp.identity(@peer, [])
      token_hash = ClientIp.token_hash(TokenHash.generate())

      assert ClientIp.posting_context(identity, token_hash) == %{
               anonymous: %{
                 ip_hash: identity.ip_hash,
                 net_scope: :ipv4_24,
                 net_hash: identity.net_hash,
                 token_hash: token_hash
               }
             }
    end

    test "drops the values it does not have" do
      identity = ClientIp.identity(@peer, [])

      assert ClientIp.posting_context(identity, nil) == %{
               anonymous: %{
                 ip_hash: identity.ip_hash,
                 net_scope: identity.net_scope,
                 net_hash: identity.net_hash
               }
             }

      token_hash = ClientIp.token_hash(TokenHash.generate())

      assert ClientIp.posting_context(nil, token_hash) == %{anonymous: %{token_hash: token_hash}}
    end

    test "is empty when there is neither an address nor a token" do
      assert ClientIp.posting_context(nil, nil) == %{}
    end

    test "never carries a raw token, only its hash" do
      raw = TokenHash.generate()
      context = ClientIp.posting_context(ClientIp.identity(@peer, []), ClientIp.token_hash(raw))

      refute inspect(context) =~ raw
      assert context.anonymous.token_hash == TokenHash.hash(raw)
    end
  end
end
