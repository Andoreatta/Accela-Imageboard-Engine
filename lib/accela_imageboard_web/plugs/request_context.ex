defmodule AccelaImageboardWeb.Plugs.RequestContext do
  @moduledoc """
  Computes the anonymous poster identity for the request and stores it where the
  Ash layer can read it.

  Identity = `AccelaImageboard.Security.IpHash.hash/1` of the client IP, resolved
  by `AccelaImageboardWeb.ClientIp` (which also decides whether a forwarded header
  may be believed). Raw IPs are never persisted; the hash is a keyed HMAC (server
  secret), stable per client, impossible to reverse without the secret.

  The result is exposed as `conn.private[:accela_ip_hash]` only - never as an
  assign - so a template cannot leak the poster hash by accident.
  """

  @behaviour Plug

  import Plug.Conn, only: [put_private: 3]

  alias AccelaImageboardWeb.ClientIp

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts), do: put_private(conn, :accela_ip_hash, ClientIp.from_conn(conn))
end
