defmodule AccelaImageboardWeb.Plugs.SecureHeaders do
  @moduledoc """
  Defense-in-depth response headers for the whole app.

  The default Content-Security-Policy baked into this module is the strict,
  production-grade one — `script-src 'self'` with no `unsafe-inline`, and
  `connect-src 'self'` only (LiveView reconnects to the same origin, so a
  `wss:` wildcard would only widen the blast radius of an XSS). It is
  deliberately **not** chosen with `Mix.env/0`: `Mix` is not available inside a
  `mix release`, so a build-time branch here would either crash on every
  request or ship dev headers to production.

  Relaxed policies belong in the environment config, e.g. `config/dev.exs`
  widens the policy for code reloading:

      config :accela_imageboard, AccelaImageboardWeb.Plugs.SecureHeaders,
        content_security_policy: "...",
        permissions_policy: "camera=()",
        hotlink_protection: true

  Notes:

    * images are served through our own controller (never statically), so
      `img-src 'self'` is enough;
    * `frame-ancestors 'none'` + `X-Frame-Options: DENY` kill clickjacking;
    * `Cross-Origin-Resource-Policy: same-origin` blocks third parties from
      hotlinking our uploaded images (set `hotlink_protection: false` to drop
      this header if you ever want embeds elsewhere);
    * `Strict-Transport-Security` is only emitted for https requests. It ships
      `includeSubDomains` but **not** `preload`: preload, and the browsers'
      https-only detection of the apex domain, depend on the edge proxy that
      terminates TLS (it must not serve plain http), so enabling them is an
      operator decision documented here rather than a kernel default.
  """

  import Plug.Conn, only: [put_resp_header: 3]

  @behaviour Plug

  @default_csp "default-src 'self'; " <>
                 "script-src 'self'; " <>
                 "style-src 'self' 'unsafe-inline'; " <>
                 "img-src 'self' data:; " <>
                 "font-src 'self'; " <>
                 "connect-src 'self'; " <>
                 "frame-ancestors 'none'; " <>
                 "base-uri 'self'; form-action 'self'; object-src 'none'"

  @default_permissions_policy "camera=(), microphone=(), geolocation=(), payment=()"

  @hsts "max-age=31536000; includeSubDomains"

  @base_headers [
    {"x-content-type-options", "nosniff"},
    {"x-frame-options", "DENY"},
    {"referrer-policy", "strict-origin-when-cross-origin"},
    {"cross-origin-opener-policy", "same-origin"},
    {"cross-origin-embedder-policy", "require-corp"},
    {"x-permitted-cross-domain-policies", "none"}
  ]

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    config = Application.get_env(:accela_imageboard, __MODULE__, [])

    (policy_headers(config) ++ hotlink_headers(config) ++ hsts_headers(conn))
    |> Enum.reduce(conn, fn {header, value}, conn -> put_resp_header(conn, header, value) end)
  end

  defp policy_headers(config) do
    [
      {"content-security-policy", config_value(config, :content_security_policy, @default_csp)},
      {"permissions-policy",
       config_value(config, :permissions_policy, @default_permissions_policy)}
      | @base_headers
    ]
  end

  defp hotlink_headers(config) do
    if config_value(config, :hotlink_protection, true) do
      [{"cross-origin-resource-policy", "same-origin"}]
    else
      []
    end
  end

  defp hsts_headers(%{scheme: :https}), do: [{"strict-transport-security", @hsts}]
  defp hsts_headers(_conn), do: []

  # A malformed config value must not take every request down: unknown shapes fall
  # back to the strict default.
  defp config_value(config, key, default) when is_list(config) do
    case Keyword.get(config, key) do
      value when value in [nil, ""] -> default
      value -> value
    end
  end

  defp config_value(_config, _key, default), do: default
end
