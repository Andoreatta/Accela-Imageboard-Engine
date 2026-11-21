import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/accela_imageboard start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :accela_imageboard, AccelaImageboardWeb.Endpoint, server: true
end

# Reads a required environment variable, failing fast both when it is missing and
# when it is empty: an empty secret is worse than a missing one, because it
# silently weakens signatures instead of stopping the boot.
require_env = fn name ->
  case System.get_env(name) do
    value when is_binary(value) and value != "" ->
      value

    _missing_or_empty ->
      raise """
      environment variable #{name} is missing or empty.

      Generate a strong value with: mix phx.gen.secret
      """
  end
end

config :accela_imageboard, AccelaImageboardWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("PORT", "4000"))]

# Reverse proxies whose `X-Forwarded-For` we believe, as a comma separated list of
# IPs and/or CIDR blocks (e.g. "10.0.0.0/8,2001:db8::/32"). Empty by default:
# without it `conn.remote_ip` is authoritative and a forged header is ignored —
# but behind a proxy that also means every visitor shares one poster hash, so set
# it when there is a proxy in front of the node. See
# AccelaImageboardWeb.Plugs.RequestContext.
config :accela_imageboard,
       :trusted_proxies,
       System.get_env("TRUSTED_PROXIES", "")
       |> String.split(",", trim: true)
       |> Enum.map(&String.trim/1)
       |> Enum.reject(&(&1 == ""))

if config_env() == :dev do
  # Reload browser tabs when matching files change.
  config :accela_imageboard, AccelaImageboardWeb.Endpoint,
    live_reload: [
      web_console_logger: true,
      patterns: [
        # Static assets, except user uploads
        ~r"priv/static/(?!uploads/).*\.(js|css|png|jpeg|jpg|gif|svg)$"E,
        # Gettext translations
        ~r"priv/gettext/.*\.po$"E,
        # Router, Controllers, LiveViews and LiveComponents
        ~r"lib/accela_imageboard_web/router\.ex$"E,
        ~r"lib/accela_imageboard_web/(controllers|live|components)/.*\.(ex|heex)$"E
      ]
    ]
end

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :accela_imageboard, AccelaImageboard.Repo,
    # ssl: true,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    # For machines with several cores, consider starting multiple pools of `pool_size`
    # pool_count: 4,
    socket_options: maybe_ipv6

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"

  config :accela_imageboard, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :accela_imageboard, AccelaImageboardWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://bandit.hexdocs.pm/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base

  # AshAuthentication signs every token (and derives its key material) from this
  # secret, which `AccelaImageboard.Secrets` reads out of OTP config. It must be
  # present and non-empty at boot: an empty signing secret would let anybody mint
  # valid authentication tokens.
  config :accela_imageboard, :token_signing_secret, require_env.("TOKEN_SIGNING_SECRET")

  # Pepper for the anonymous poster hashes (`AccelaImageboard.Security.IpHash`).
  # Required, with no silent fallback: a known pepper lets anyone brute-force the
  # small IPv4 space back to the raw IP behind every poster hash.
  config :accela_imageboard, AccelaImageboard.Security.IpHash,
    secret: require_env.("IP_HASH_SECRET")

  # The session cookie is `Secure` — see lib/accela_imageboard_web/endpoint.ex.
  # That flag is compiled into the endpoint, so a runtime variable cannot flip
  # it; an operator who believes they disabled it gets a boot failure instead of
  # an unknowingly insecure deployment.
  case System.get_env("SESSION_COOKIE_SECURE") do
    value when value in ~w(false 0 no) ->
      raise """
      SESSION_COOKIE_SECURE=#{value} is not supported in production.

      The session cookie must be sent over HTTPS only. Remove the variable — the
      flag is compiled into the endpoint at build time — or set it to true.
      """

    _enabled_or_unset ->
      config :accela_imageboard, :session_cookie_secure, true
  end

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :accela_imageboard, AccelaImageboardWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://plug.hexdocs.pm/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :accela_imageboard, AccelaImageboardWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.
end
