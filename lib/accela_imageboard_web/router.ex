defmodule AccelaImageboardWeb.Router do
  use AccelaImageboardWeb, :router

  use AshAuthentication.Phoenix.Router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {AccelaImageboardWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug AccelaImageboardWeb.Plugs.SecureHeaders
    plug AccelaImageboardWeb.Plugs.RequestContext
    plug :load_from_session
    plug :set_scope, scope: AccelaImageboard.Accounts.Scope, default_scope?: true
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug :load_from_bearer
    plug :set_scope, scope: AccelaImageboard.Accounts.Scope, default_scope?: true
  end

  scope "/", AccelaImageboardWeb do
    pipe_through :browser

    ash_authentication_live_session :authenticated_routes,
      scope: AccelaImageboard.Accounts.Scope,
      default_scope: :user do
      # in each liveview, add one of the following at the top of the module:
      #
      # If an authenticated user must be present:
      # on_mount {AccelaImageboardWeb.LiveUserAuth, :live_user_required}
      #
      # If an authenticated user *may* be present:
      # on_mount {AccelaImageboardWeb.LiveUserAuth, :live_user_optional}
      #
      # If an authenticated user must *not* be present:
      # on_mount {AccelaImageboardWeb.LiveUserAuth, :live_no_user}
    end
  end

  scope "/", AccelaImageboardWeb do
    pipe_through :browser

    get "/", PageController, :home
    auth_routes AuthController, AccelaImageboard.Accounts.User, path: "/auth"

    sign_out_route AuthController, "/sign-out",
      overrides: [AccelaImageboardWeb.AuthOverrides, AshAuthentication.Phoenix.Overrides.Default]

    # Sign-in only. Self-service registration is intentionally not mounted:
    # this deployment holds staff accounts, and an anonymous visitor must not be
    # able to create one. Dropping `register_path` removes both the `/register`
    # page and the "Register" link from the sign-in form. The API endpoint
    # `POST /auth/user/register` is separately closed by the resource's
    # `registration_enabled?` setting (see lib/accela_imageboard/accounts/user.ex).
    sign_in_route reset_path: "/reset",
                  auth_routes_prefix: "/auth",
                  on_mount: [{AccelaImageboardWeb.LiveUserAuth, :live_no_user}],
                  overrides: [
                    AccelaImageboardWeb.AuthOverrides,
                    AshAuthentication.Phoenix.Overrides.Default
                  ]

    # Remove this if you do not want to use the reset password feature
    reset_route auth_routes_prefix: "/auth",
                overrides: [
                  AccelaImageboardWeb.AuthOverrides,
                  AshAuthentication.Phoenix.Overrides.Default
                ]

    # Remove this if you do not use the confirmation strategy
    confirm_route AccelaImageboard.Accounts.User, :confirm_new_user,
      auth_routes_prefix: "/auth",
      overrides: [AccelaImageboardWeb.AuthOverrides, AshAuthentication.Phoenix.Overrides.Default]
  end

  # Other scopes may use custom stacks.
  # scope "/api", AccelaImageboardWeb do
  #   pipe_through :api
  # end

  # Developer tooling (/dev, /admin) is gated twice: the routes are only
  # compiled in when `:dev_routes` is set, and every request must then pass HTTP
  # Basic authentication from `:dev_admin_basic_auth` (see
  # `AccelaImageboardWeb.Plugs.DevAdminAuth`, which fails closed when the
  # credentials are not configured). Keep in mind that these LiveViews talk to
  # the app over the shared `/live` socket, which is not behind this pipeline:
  # never enable `:dev_routes` in a build that is reachable from the internet.
  if Application.compile_env(:accela_imageboard, :dev_routes) do
    import Phoenix.LiveDashboard.Router
    import AshAdmin.Router

    pipeline :dev_admin do
      # Only the guard: `:browser` already handles accepts, session, CSRF and the
      # security headers, and both scopes below run through both pipelines.
      plug AccelaImageboardWeb.Plugs.DevAdminAuth
    end

    scope "/dev" do
      pipe_through [:browser, :dev_admin]

      live_dashboard "/dashboard", metrics: AccelaImageboardWeb.Telemetry
    end

    scope "/admin" do
      pipe_through [:browser, :dev_admin]

      ash_admin "/"
    end
  end
end
