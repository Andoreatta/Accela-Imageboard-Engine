defmodule AccelaImageboardWeb.Plugs.RequestContext do
  @moduledoc """
  Establishes the anonymous poster identity for the request: the address-derived
  hashes and a server-issued anonymous session token.

  ## What it computes

    * `conn.private[:accela_poster_identity]` - `%{ip_hash: ..., net_scope: ...,
      net_hash: ...}`, resolved by `AccelaImageboardWeb.ClientIp` (which also decides
      whether a forwarded header may be believed), or `nil` when there is no peer
      address;
    * `conn.private[:accela_ip_hash]` - the exact-address hash on its own, kept for
      the code paths that only want that one identifier;
    * `conn.private[:accela_anon_token]` - the raw anonymous session token;
    * `conn.private[:accela_anon_token_hash]` - its keyed hash, which is what the
      domain stores so a returning browser is recognised.

  ## Why the raw token never leaves `private`

  The token *is* the credential: anyone holding it can impersonate this poster until
  the session ends. It therefore lives in `conn.private`, which templates cannot read;
  it is never assigned, never rendered and never logged. Only its hash travels on -
  into the Ash action context by the LiveViews, and into the database by the domain.

  ## Where the token rides

  In the session, under `"accela_anon"`, inside the endpoint's session cookie: signed
  with the application secret, `httpOnly` (no JavaScript access) and `sameSite: Lax`
  (see `AccelaImageboardWeb.Endpoint`). A cleared cookie simply means the next request
  mints a new token - which is exactly the identifier rotation that the address-based
  hashes cover for.

  A token is only honoured when it is a binary of 16..200 bytes; anything else in the
  session (an inflated, truncated or hand-crafted value) is replaced, so a client
  cannot pick its own identifier. Writing needs a session store: on a connection
  without one the request is attributed by its address alone and no token is set.
  """

  @behaviour Plug

  import Plug.Conn, only: [fetch_session: 1, put_private: 3, put_session: 3]

  alias AccelaImageboard.Security.TokenHash
  alias AccelaImageboardWeb.ClientIp

  @session_key "accela_anon"
  @min_token_bytes 16
  @max_token_bytes 200

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    conn = ensure_session(conn)
    identity = ClientIp.identity_from_conn(conn)
    {conn, token} = ensure_token(conn)

    conn
    |> put_private(:accela_ip_hash, identity && identity.ip_hash)
    |> put_private(:accela_poster_identity, identity)
    |> put_private(:accela_anon_token, token)
    |> put_private(:accela_anon_token_hash, ClientIp.token_hash(token))
  end

  # The `:browser` pipeline fetches the session before this plug runs, and
  # `fetch_session/1` is idempotent, so this only matters for a caller that runs the
  # plug on its own; a connection with no session store is left untouched.
  defp ensure_session(conn) do
    case conn.private do
      %{plug_session_fetch: :done} -> conn
      %{plug_session_fetcher: _fetcher} -> fetch_session(conn)
      _no_session_store -> conn
    end
  end

  defp ensure_token(conn) do
    case stored_token(conn) do
      token when is_binary(token) ->
        if valid_token?(token), do: {conn, token}, else: issue_token(conn)

      _absent_or_not_a_binary ->
        issue_token(conn)
    end
  end

  defp stored_token(%{private: %{plug_session: session}}) when is_map(session),
    do: Map.get(session, @session_key)

  defp stored_token(_not_fetched), do: nil

  # Only a token this plug could have minted is reused; anything else is replaced, so
  # the identifier can never be chosen by the client.
  defp valid_token?(token), do: byte_size(token) in @min_token_bytes..@max_token_bytes

  # A token can only be minted where a session exists to hold it. Without one the
  # request is attributed by its address alone.
  defp issue_token(conn) do
    if session_usable?(conn) do
      token = TokenHash.generate()
      {put_session(conn, @session_key, token), token}
    else
      {conn, nil}
    end
  end

  defp session_usable?(conn) do
    case conn.private do
      %{plug_session_fetch: :done} -> true
      %{plug_session_fetcher: _fetcher} -> true
      _no_session_store -> false
    end
  end
end
