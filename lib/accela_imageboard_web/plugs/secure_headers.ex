defmodule AccelaImageboardWeb.Plugs.SecureHeaders do
  @moduledoc """
  Defense-in-depth response headers for the whole app.

  The CSP is strict by default and relaxed in dev (code reload, LiveDashboard
  and esbuild need ws/inline). Every value is overridable through config:

      config :accela_imageboard, AccelaImageboardWeb.Plugs.SecureHeaders,
        content_security_policy: "...",
        hotlink_protection: true

  Notes:
  * images are served through our own controller (never statically), so
    `img-src 'self'` is enough;
  * `frame-ancestors 'none'` + `X-Frame-Options: DENY` kill clickjacking;
  * `Cross-Origin-Resource-Policy: same-origin` blocks third parties from
    hotlinking our uploaded images (set `hotlink_protection: false` to drop
    this header if you ever want embeds elsewhere).
  """

  import Plug.Conn

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    config = Application.get_env(:accela_imageboard, __MODULE__, [])

    csp =
      Keyword.get(config, :content_security_policy) ||
        default_csp(Mix.env())

    headers = [
      {"content-security-policy", csp},
      {"x-content-type-options", "nosniff"},
      {"x-frame-options", "DENY"},
      {"referrer-policy", "strict-origin-when-cross-origin"},
      {"cross-origin-opener-policy", "same-origin"},
      {"cross-origin-embedder-policy", "require-corp"},
      {"x-permitted-cross-domain-policies", "none"}
    ]

    headers =
      if Keyword.get(config, :hotlink_protection, true) do
        [{"cross-origin-resource-policy", "same-origin"} | headers]
      else
        headers
      end

    headers =
      if conn.scheme == :https do
        [{"strict-transport-security", "max-age=31536000; includeSubDomains"} | headers]
      else
        headers
      end

    Enum.reduce(headers, conn, fn {header, value}, conn ->
      put_resp_header(conn, header, value)
    end)
  end

  defp default_csp(:dev) do
    # Live reload/dashboard + esbuild HMR need ws and inline styles.
    "default-src 'self'; " <>
      "script-src 'self' 'unsafe-inline'; " <>
      "style-src 'self' 'unsafe-inline'; " <>
      "img-src 'self' data:; " <>
      "font-src 'self'; " <>
      "connect-src 'self' ws://localhost:* wss://localhost:*; " <>
      "frame-ancestors 'none'; " <>
      "base-uri 'self'; form-action 'self'; object-src 'none'"
  end

  defp default_csp(_) do
    "default-src 'self'; " <>
      "script-src 'self'; " <>
      "style-src 'self' 'unsafe-inline'; " <>
      "img-src 'self' data:; " <>
      "font-src 'self'; " <>
      "connect-src 'self' wss:; " <>
      "frame-ancestors 'none'; " <>
      "base-uri 'self'; form-action 'self'; object-src 'none'"
  end
end
