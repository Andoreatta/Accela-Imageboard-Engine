defmodule AccelaImageboardWeb.LiveIdentity do
  @moduledoc """
  The anonymous poster identity as a LiveView sees it, in one place.

  A LiveView gets the same three identifiers the HTTP plug computes, from the same
  sources, so posting through a LiveView cannot be attributed differently from posting
  through a controller:

    * the peer address and the forwarded headers, resolved by
      `AccelaImageboardWeb.ClientIp` (a forwarded header is believed only when the peer
      is a configured trusted proxy);
    * the anonymous session token the request-context plug minted into the session.

  Nothing here is read from params, assigns or the URL: the identity is derived from
  the connection at mount and then carried in the socket.

  ## Two shapes of connect info

  `Phoenix.LiveView.get_connect_info/2` serves `:peer_data`, `:x_headers` and `:session`
  when the socket was connected with a map, which is what the real transport does
  (`connect_info: [:peer_data, :x_headers, session: @session_options]` in the endpoint).
  A dead render and a LiveView test, however, are handed the `%Plug.Conn{}` itself, for
  which `:session` is not an available key - the fetched session lives in the conn's
  private instead. Both shapes are handled here, and a missing session simply means
  "no token": the poster is then identified by address alone.
  """

  import Phoenix.LiveView, only: [get_connect_info: 2]

  alias AccelaImageboardWeb.ClientIp

  @session_key "accela_anon"

  @doc """
  The Ash action context (contract v2) for the connection behind `socket`.

  Returns `%{anonymous: %{ip_hash: ..., net_scope: ..., net_hash: ..., token_hash: ...}}`
  with the values that are actually available, or `%{}` when there is neither an
  address nor a token - the domain then refuses to attribute the action.
  """
  @spec posting_context(Phoenix.LiveView.Socket.t()) :: map()
  def posting_context(socket) do
    ClientIp.posting_context(identity(socket), ClientIp.token_hash(session_token(socket)))
  end

  @doc """
  The address-derived part of the identity, or `nil` when the socket has no peer.
  """
  @spec identity(Phoenix.LiveView.Socket.t()) :: ClientIp.identity() | nil
  def identity(socket) do
    peer_data = get_connect_info(socket, :peer_data)
    headers = get_connect_info(socket, :x_headers) || []

    ClientIp.identity(peer_data && peer_data.address, headers)
  end

  @doc """
  The raw anonymous session token the connection carries, or `nil`.

  The raw token never leaves this module's caller: only
  `ClientIp.posting_context/2`'s hash of it is passed on to the domain.
  """
  @spec session_token(Phoenix.LiveView.Socket.t()) :: String.t() | nil
  def session_token(socket) do
    case socket.private[:connect_info] do
      %Plug.Conn{} = conn -> conn_token(conn)
      %{} = connect_info -> token_in(Map.get(connect_info, :session))
      _absent -> nil
    end
  end

  defp conn_token(%Plug.Conn{private: %{plug_session: session}}), do: token_in(session)
  defp conn_token(_conn), do: nil

  defp token_in(%{} = session), do: Map.get(session, @session_key)
  defp token_in(_no_session), do: nil
end
