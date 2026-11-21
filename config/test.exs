import Config
config :accela_imageboard, token_signing_secret: "8PWH5BW5QuusN3r0tl3LOUqy8VIg3akA"
config :bcrypt_elixir, log_rounds: 1
config :ash, disable_async?: true

# Oban in tests: `:manual` disables queues, plugins, the stager and peers, so no
# job ever runs behind a test's back, while `Oban.Testing` assertions
# (`assert_enqueued/1`) still work against the database.
#
# `:manual` also makes Oban verify at boot that the `oban_jobs` tables are
# migrated (it raises otherwise), which they are: `priv/repo/migrations/
# *_add_oban_jobs.exs` runs as part of the `test` alias' `ash.setup`.
config :accela_imageboard, Oban,
  testing: :manual,
  queues: false,
  plugins: false

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :accela_imageboard, AccelaImageboard.Repo,
  username: System.get_env("DB_USERNAME", "postgres"),
  password: System.get_env("DB_PASSWORD", "accela_dev"),
  hostname: System.get_env("DB_HOST", "localhost"),
  database: "accela_imageboard_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :accela_imageboard, AccelaImageboardWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "j/8k00E7AAQD+HeO1dJOosmsBrBjp+sAvZAmnbazJvUQ3R7PyBRCyIEBHENeORS6",
  server: false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
