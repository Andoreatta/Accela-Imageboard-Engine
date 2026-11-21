defmodule AccelaImageboard.MixProject do
  use Mix.Project

  def project do
    [
      app: :accela_imageboard,
      version: "0.1.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      compilers: [:phoenix_live_view] ++ Mix.compilers(),
      listeners: [Phoenix.CodeReloader]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {AccelaImageboard.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test, check: :test, "coveralls.html": :test]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:simple_sat, "~> 0.1"},
      {:ash_oban, "~> 0.10"},
      {:ash_state_machine, "~> 0.3"},
      {:ash_archival, "~> 2.0"},
      {:ash_paper_trail, "~> 0.8"},
      {:ash_admin, "~> 1.0"},
      {:ash_authentication_phoenix, "~> 3.0.0-rc"},
      {:ash_authentication, "~> 5.0.0-rc.18"},
      {:ash_phoenix, "~> 2.0"},
      {:ash_postgres, "~> 2.0"},
      {:phoenix, "~> 1.8.17"},
      {:phoenix_ecto, "~> 4.5"},
      {:ecto_sql, "~> 3.13"},
      {:postgrex, ">= 0.0.0"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 1.2.0"},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:phoenix_live_dashboard, "~> 0.8.3"},
      {:esbuild, "~> 0.10", runtime: Mix.env() == :dev},
      {:tailwind, "~> 0.5", runtime: Mix.env() == :dev},
      {:heroicons,
       github: "tailwindlabs/heroicons",
       tag: "v2.2.0",
       sparse: "optimized",
       app: false,
       compile: false,
       depth: 1},
      {:daisyui,
       github: "saadeghi/daisyui",
       tag: "v5.5.20",
       sparse: "packages/bundle",
       app: false,
       compile: false,
       depth: 1},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},
      {:gettext, "~> 1.0"},
      {:jason, "~> 1.2"},
      {:dns_cluster, "~> 0.2.0"},
      {:bandit, "~> 1.5"},
      # ash_authentication hard-depends on bcrypt_elixir (NIF, needs MSVC on
      # Windows). We satisfy the graph with a vendored stub and hash passwords
      # with pure-OTP PBKDF2 instead — see AccelaImageboard.Auth.Pbkdf2HashProvider.
      {:bcrypt_elixir, path: "vendor/bcrypt_elixir_stub", override: true},

      # Anonymous-post rate limiting (per keyed IP hash), maintained & active.
      {:hammer, "~> 7.6"},

      # Quality & security tooling
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.21", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18.5", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.38", only: :dev, runtime: false},
      {:mix_test_watch, "~> 1.3", only: :dev, runtime: false},
      {:igniter, "~> 0.6", only: [:dev, :test]}
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      setup: ["deps.get", "ash.setup", "assets.setup", "assets.build", "run priv/repo/seeds.exs"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ash.setup --quiet", "test"],
      "assets.setup": ["tailwind.install --if-missing", "esbuild.install --if-missing"],
      "assets.build": ["compile", "tailwind accela_imageboard", "esbuild accela_imageboard"],
      "assets.deploy": [
        "tailwind accela_imageboard --minify",
        "esbuild accela_imageboard --minify",
        "phx.digest"
      ],
      precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "test"],
      # Full quality & security gate — run before every push.
      check: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo",
        "sobelow",
        "doctor",
        "test --raise"
      ],
      # Run manually or in CI: `mix hex.audit` cannot be invoked from an
      # alias (Hex tasks are not dep tasks) — it audits the lockfile for
      # retired packages and security advisories.
      "coveralls.html": ["test coveralls.html --raise"]
    ]
  end
end
