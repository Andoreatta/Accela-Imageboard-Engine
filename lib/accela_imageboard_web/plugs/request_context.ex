defmodule AccelaImageboardWeb.Plugs.RequestContext do
  @moduledoc """
  Computes the anonymous poster identity for the request and stores it
  where the Ash layer can read it.

  Identity = `AccelaImageboard.Security.IpHash.hash/1` of the client IP.
  Raw IPs are never persisted; the hash is a keyed HMAC (server secret),
  stable per client, impossible to reverse without the secret.

  Proxy note: only trust a forwarded IP when `TRUSTED_PROXIES` is configured
  in config — otherwise Bandit's `conn.remote_ip` is authoritative.
  """

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    ip_hash = conn |> client_ip() |> AccelaImageboard.Security.IpHash.hash()

    conn
    |> Plug.Conn.put_private(:accela_ip_hash, ip_hash)
    |> Plug.Conn.assign(:anonymous_ip_hash, ip_hash)
  end

  defp client_ip(conn) do
    trusted = Application.get_env(:accela_imageboard, :trusted_proxies, [])

    if trusted != [] do
      forwarded = Plug.Conn.get_req_header(conn, "x-forwarded-for")

      case forwarded do
        [first | _] ->
          first |> String.split(",") |> List.first() |> String.trim()

        [] ->
          conn.remote_ip
      end
    else
      conn.remote_ip
    end
  end
end
