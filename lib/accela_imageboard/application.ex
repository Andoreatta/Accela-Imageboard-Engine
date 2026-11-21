defmodule AccelaImageboard.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      AccelaImageboardWeb.Telemetry,
      AccelaImageboard.Repo,
      {DNSCluster, query: Application.get_env(:accela_imageboard, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: AccelaImageboard.PubSub},
      # Anonymous-post rate limiting (ETS-backed, keyed by hashed IP)
      {AccelaImageboard.RateLimits, clean_period: :timer.minutes(10)},
      # Start a worker by calling: AccelaImageboard.Worker.start_link(arg)
      # {AccelaImageboard.Worker, arg},
      # Start to serve requests, typically the last entry
      AccelaImageboardWeb.Endpoint,
      {AshAuthentication.Supervisor, [otp_app: :accela_imageboard]}
    ]

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: AccelaImageboard.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    AccelaImageboardWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
