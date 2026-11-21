defmodule AccelaImageboardWeb.Plugs.DevAdminAuth do
  @moduledoc """
  Fail-closed HTTP Basic authentication gate for the dev-only tooling routes.

  `/dev` (LiveDashboard) and `/admin` (AshAdmin) only exist when
  `config :accela_imageboard, :dev_routes` is compiled in, but that is a single
  build-flag mistake away from shipping a dashboard and an admin UI whose own
  "toggle authorizing" control disables every Ash policy. This plug adds a
  second, request-time gate so those routes can never be reached anonymously —
  even if `dev_routes` leaks into a non-dev build.

  Credentials are read at request time from

      config :accela_imageboard, :dev_admin_basic_auth,
        username: System.get_env("DEV_ADMIN_USERNAME", "admin"),
        password: System.get_env("DEV_ADMIN_PASSWORD")

  When either value is missing or empty the request is rejected instead of
  allowed: no configuration means no access, never "open by accident".
  """

  @behaviour Plug

  import Plug.Conn, only: [halt: 1]

  @realm "Accela dev tools"

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case credentials() do
      {:ok, username, password} ->
        Plug.BasicAuth.basic_auth(conn, username: username, password: password, realm: @realm)

      :error ->
        conn
        |> Plug.BasicAuth.request_basic_auth(realm: @realm)
        |> halt()
    end
  end

  defp credentials do
    config =
      :accela_imageboard
      |> Application.get_env(:dev_admin_basic_auth, [])
      |> List.wrap()

    with true <- Keyword.keyword?(config),
         {:ok, username} <- fetch(config, :username),
         {:ok, password} <- fetch(config, :password) do
      {:ok, username, password}
    else
      _missing_or_malformed -> :error
    end
  end

  defp fetch(config, key) do
    case Keyword.get(config, key) do
      value when is_binary(value) ->
        if String.trim(value) == "", do: :error, else: {:ok, value}

      _missing_or_invalid ->
        :error
    end
  end
end
