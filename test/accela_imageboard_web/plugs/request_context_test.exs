defmodule AccelaImageboardWeb.Plugs.RequestContextTest do
  @moduledoc """
  The request-context plug is where a poster's identifiers are minted, so these tests
  pin three things: the token is issued once and reused (never chosen by the client),
  the private keys are exactly the documented ones (the raw token never becomes an
  assign), and a connection without a session is still attributed by its address.
  """

  use AccelaImageboardWeb.ConnCase, async: false

  import AccelaImageboardWeb.BoardCase, only: [connect_as: 2]

  alias AccelaImageboard.Security.IpHash
  alias AccelaImageboard.Security.TokenHash
  alias AccelaImageboardWeb.Plugs.RequestContext

  @peer {203, 0, 113, 9}
  @other_peer {198, 51, 100, 7}

  describe "call/2 on a connection with a session" do
    test "issues a token into the session when there is none" do
      conn = RequestContext.call(session_conn(), [])

      token = get_session(conn, "accela_anon")

      assert is_binary(token)
      assert byte_size(token) >= 32
      assert conn.private[:accela_anon_token] == token
      assert conn.private[:accela_anon_token_hash] == TokenHash.hash(token)
    end

    test "reuses a token the session already carries" do
      existing = TokenHash.generate()

      conn = RequestContext.call(session_conn(%{"accela_anon" => existing}), [])

      assert get_session(conn, "accela_anon") == existing
      assert conn.private[:accela_anon_token] == existing
      assert conn.private[:accela_anon_token_hash] == TokenHash.hash(existing)
    end

    test "replaces a token that is too short to be one of ours" do
      conn = RequestContext.call(session_conn(%{"accela_anon" => "short"}), [])

      token = get_session(conn, "accela_anon")

      refute token == "short"
      assert byte_size(token) >= 32
      assert conn.private[:accela_anon_token_hash] == TokenHash.hash(token)
    end

    test "replaces a token that is oversized or not a binary" do
      for bogus <- [:atom_token, 123, String.duplicate("a", 201)] do
        conn = RequestContext.call(session_conn(%{"accela_anon" => bogus}), [])

        token = get_session(conn, "accela_anon")

        assert is_binary(token)
        assert byte_size(token) in 32..200, "expected #{inspect(bogus)} to be replaced"
        assert conn.private[:accela_anon_token] == token
      end
    end

    test "never regenerates the token it just accepted, so the identity is stable" do
      first = RequestContext.call(session_conn(), [])
      identity = conn_from_session(first)

      second = RequestContext.call(identity, [])

      assert second.private[:accela_anon_token] == first.private[:accela_anon_token]
      assert second.private[:accela_anon_token_hash] == first.private[:accela_anon_token_hash]
    end
  end

  describe "the private it populates" do
    test "holds the identity, the ip hash, the raw token and its hash - and no assigns" do
      conn = RequestContext.call(session_conn(), [])

      identity = conn.private[:accela_poster_identity]

      assert identity.ip_hash == IpHash.hash(@peer)
      assert {:ipv4_24, net_hash} = IpHash.net(@peer)
      assert identity.net_scope == :ipv4_24
      assert identity.net_hash == net_hash

      assert conn.private[:accela_ip_hash] == identity.ip_hash
      assert is_binary(conn.private[:accela_anon_token])

      assert conn.private[:accela_anon_token_hash] ==
               TokenHash.hash(conn.private[:accela_anon_token])

      # The raw token is a credential: it must not be reachable from a template.
      assert conn.assigns == %{}
    end

    test "is the same identity for two requests from the same connection" do
      first = RequestContext.call(session_conn(), [])
      second = RequestContext.call(conn_from_session(first), [])

      assert second.private[:accela_poster_identity] == first.private[:accela_poster_identity]
    end

    test "carries a nil identity but still a token when the peer is unknown" do
      conn = RequestContext.call(%{session_conn() | remote_ip: nil}, [])

      assert conn.private[:accela_poster_identity] == nil
      assert conn.private[:accela_ip_hash] == nil
      assert is_binary(conn.private[:accela_anon_token])
      assert is_binary(conn.private[:accela_anon_token_hash])
    end
  end

  describe "call/2 without a session store" do
    test "does not raise and attributes by address alone" do
      conn = %{Plug.Test.conn(:get, "/") | remote_ip: @peer}

      result = RequestContext.call(conn, [])

      assert result.private[:accela_ip_hash] == IpHash.hash(@peer)
      assert result.private[:accela_poster_identity].net_scope == :ipv4_24
      assert result.private[:accela_anon_token] == nil
      assert result.private[:accela_anon_token_hash] == nil
      refute Map.has_key?(result.private, :plug_session)
    end
  end

  describe "through the browser pipeline" do
    test "mints the token into the signed session cookie on a real request", %{conn: conn} do
      conn = get(connect_as(conn, @peer), "/")

      token = get_session(conn, "accela_anon")

      assert is_binary(token)
      assert conn.private[:accela_anon_token] == token
      assert conn.private[:accela_poster_identity].ip_hash == IpHash.hash(@peer)
      assert conn.private[:accela_anon_token_hash] == TokenHash.hash(token)
      assert Map.has_key?(conn.resp_cookies, "_accela_imageboard_key")
    end

    test "reuses the token carried by the request cookie", %{conn: conn} do
      existing = TokenHash.generate()

      conn =
        conn
        |> Plug.Test.init_test_session(%{"accela_anon" => existing})
        |> get("/")

      assert get_session(conn, "accela_anon") == existing
      assert conn.private[:accela_anon_token_hash] == TokenHash.hash(existing)
    end

    test "keeps two different visitors apart", %{conn: conn} do
      first = get(connect_as(conn, @peer), "/")
      second = get(connect_as(build_conn(), @other_peer), "/")

      refute first.private[:accela_anon_token] == second.private[:accela_anon_token]
      refute first.private[:accela_ip_hash] == second.private[:accela_ip_hash]
    end
  end

  ## helpers

  # A connection that can hold a session, as the browser pipeline leaves it.
  defp session_conn(session \\ %{}) do
    :get
    |> Plug.Test.conn("/")
    |> Map.put(:remote_ip, @peer)
    |> Plug.Test.init_test_session(session)
  end

  # Feeds the session of a previous call back into a fresh connection, the way a
  # returning browser would present its cookie.
  defp conn_from_session(previous) do
    :get
    |> Plug.Test.conn("/")
    |> Map.put(:remote_ip, @peer)
    |> Plug.Test.init_test_session(Plug.Conn.get_session(previous))
  end
end
