# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :phoenix, filter_parameters: ["password", "token"]

config :spark,
  formatter: [
    "Ash.Resource": [section_order: [:authentication, :token, :user_identity, :admin, :postgres]],
    "Ash.Domain": [section_order: [:admin]]
  ]

config :ash, known_types: [AshPostgres.Timestamptz, AshPostgres.TimestamptzUsec]

config :accela_imageboard,
  ecto_repos: [AccelaImageboard.Repo],
  generators: [timestamp_type: :utc_datetime],
  ash_domains: [AccelaImageboard.Accounts, AccelaImageboard.Boards, AccelaImageboard.Moderation]

# Background jobs (Oban, `Oban.Engines.Basic`, Postgres-backed).
#
# Started in the supervision tree after the repo it writes through, see
# `AccelaImageboard.Application`. No jobs are defined yet — AshOban is not
# applied to any resource — but the engine, its queues and its migration are in
# place so a worker only has to be added and enqueued:
#
#   * `media`   — image post-processing (thumbnails, metadata stripping)
#   * `default` — AshOban's queue and everything else
#
# `testing: :manual` in config/test.exs turns queues, plugins and the stager off
# so no job runs behind a test's back.
config :accela_imageboard, Oban,
  engine: Oban.Engines.Basic,
  repo: AccelaImageboard.Repo,
  queues: [default: 10, media: 5]

# Configure the endpoint
config :accela_imageboard, AccelaImageboardWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: AccelaImageboardWeb.ErrorHTML, json: AccelaImageboardWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: AccelaImageboard.PubSub,
  live_view: [signing_salt: "gD5oVa07"]

# Configure LiveView
config :phoenix_live_view,
  # the attribute set on all root tags. Used for Phoenix.LiveView.ColocatedCSS.
  root_tag_attribute: "phx-r"

# Session cookie hardening (see AccelaImageboardWeb.Endpoint).
#
# `secure: true` means the session cookie is only ever sent over HTTPS. The flag
# is compile-time — Plug.Session options are baked into the endpoint when it is
# compiled — so it must be set when the release is built. config/dev.exs turns it
# off for http://localhost, config/prod.exs keeps it on and config/runtime.exs
# refuses to boot a prod node that tries to disable it.
config :accela_imageboard, :session_cookie_secure, true

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  accela_imageboard: [
    # Two entry points: the LiveView bundle plus the small synchronous theme
    # bootstrap used by the root layout (an inline <script> would be blocked
    # by the production CSP's `script-src 'self'`).
    args:
      ~w(js/app.js js/theme.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.3.3",
  accela_imageboard: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Ash string length counting: codepoints matches SQL data-layer semantics,
# so `max_length` constraints actually bound stored value sizes.
config :ash, default_string_length_count: :codepoints

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
