defmodule AccelaImageboardWeb.LiveIdentityTest do
  @moduledoc """
  A LiveView sees the connection in two shapes - a connect-info map from the real
  transport and the `%Plug.Conn{}` itself in a dead render or a test - and only the map
  serves `:session` through `get_connect_info/2`. Both are pinned here, together with
  the promise that a missing session means "no token", never a crash.
  """

  use ExUnit.Case, async: false

  alias AccelaImageboard.Security.IpHash
  alias AccelaImageboard.Security.TokenHash
  alias AccelaImageboardWeb.ClientIp
  alias AccelaImageboardWeb.LiveIdentity

  @peer {203, 0, 113, 9}

  defp peer_data(ip), do: %{address: ip, port: 443, ssl_cert: nil}

  defp socket(connect_info) do
    %Phoenix.LiveView.Socket{private: %{connect_info: connect_info}}
  end

  # A conn carries its peer in the adapter payload (see Plug.Conn.get_peer_data/1),
  # which is what a dead render sees - setting remote_ip alone would not be enough.
  defp conn_with_peer(ip, session \\ %{}) do
    conn = Plug.Test.conn(:get, "/")
    {adapter, payload} = conn.adapter

    conn = %{
      conn
      | adapter: {adapter, Map.put(payload, :peer_data, %{address: ip, port: 0, ssl_cert: nil})}
    }

    Plug.Test.init_test_session(conn, session)
  end

  describe "posting_context/1 with a connect-info map (the real transport)" do
    test "carries the address identity and the session token" do
      token = TokenHash.generate()

      context =
        LiveIdentity.posting_context(
          socket(%{
            peer_data: peer_data(@peer),
            x_headers: [],
            session: %{"accela_anon" => token}
          })
        )

      identity = ClientIp.identity(@peer, [])

      assert context == %{
               anonymous: %{
                 ip_hash: identity.ip_hash,
                 net_scope: :ipv4_24,
                 net_hash: identity.net_hash,
                 token_hash: TokenHash.hash(token)
               }
             }
    end

    test "is identity-only when the session carries no token" do
      context =
        LiveIdentity.posting_context(
          socket(%{peer_data: peer_data(@peer), x_headers: [], session: %{}})
        )

      assert context.anonymous.ip_hash == IpHash.hash(@peer)
      refute Map.has_key?(context.anonymous, :token_hash)
    end

    test "is token-only when the socket has no peer address" do
      token = TokenHash.generate()

      context =
        LiveIdentity.posting_context(
          socket(%{peer_data: nil, x_headers: [], session: %{"accela_anon" => token}})
        )

      assert context == %{anonymous: %{token_hash: TokenHash.hash(token)}}
    end

    test "is empty when there is neither a peer nor a token" do
      assert LiveIdentity.posting_context(socket(%{peer_data: nil, x_headers: []})) == %{}
    end
  end

  describe "posting_context/1 with a conn (dead render, tests)" do
    test "reads the token from the conn's fetched session" do
      token = TokenHash.generate()

      context =
        LiveIdentity.posting_context(socket(conn_with_peer(@peer, %{"accela_anon" => token})))

      assert context.anonymous.ip_hash == IpHash.hash(@peer)
      assert context.anonymous.token_hash == TokenHash.hash(token)
    end

    test "falls back to address-only when the conn has no session" do
      context = LiveIdentity.posting_context(socket(conn_with_peer(@peer)))

      assert context.anonymous.ip_hash == IpHash.hash(@peer)
      refute Map.has_key?(context.anonymous, :token_hash)
    end
  end

  describe "session_token/1" do
    test "is nil for every shape that carries no token" do
      assert LiveIdentity.session_token(socket(%{peer_data: peer_data(@peer)})) == nil
      assert LiveIdentity.session_token(socket(%{session: %{}})) == nil
      assert LiveIdentity.session_token(socket(%{"not" => "a session"})) == nil
      assert LiveIdentity.session_token(socket(Plug.Test.conn(:get, "/"))) == nil
    end

    test "returns the raw token it finds" do
      token = TokenHash.generate()

      assert LiveIdentity.session_token(socket(%{session: %{"accela_anon" => token}})) == token
    end
  end

  describe "network identity" do
    test "an IPv6 peer is pinned at /64, like the HTTP path" do
      ipv6 = {0x2001, 0x0DB8, 1, 2, 0, 0, 0, 1}

      context = LiveIdentity.posting_context(socket(%{peer_data: peer_data(ipv6), x_headers: []}))

      assert context.anonymous.net_scope == :ipv6_64
      assert {_scope, net_hash} = IpHash.net(ipv6)
      assert context.anonymous.net_hash == net_hash
    end
  end
end
