defmodule AccelaImageboardWeb.AuthController do
  @moduledoc """
  Handles AshAuthentication callbacks (sign in, confirm, reset) injected by
  `auth_routes` in the router.
  """

  use AccelaImageboardWeb, :controller
  use AshAuthentication.Phoenix.Controller

  # Only local, absolute paths are accepted as a post-auth redirect target.
  # Rejections matter: a leading "//" is scheme-relative, and browsers
  # normalise "/\" into "//", so either one becomes an off-site redirect the
  # moment a request parameter ever reaches `:return_to`.
  @local_path ~r{\A/(?!/)[^\s\\]*\z}

  @doc "Successful authentication: stores the session and redirects back."
  def success(conn, activity, user, token) do
    target = return_to(conn)

    message =
      case activity do
        {:confirm_new_user, :confirm} -> "Your email address has now been confirmed"
        {:password, :reset} -> "Your password has successfully been reset"
        _ -> "You are now signed in"
      end

    conn
    |> delete_session(:return_to)
    |> store_in_session(user)
    |> set_live_socket_id(token)
    # If your resource has a different name, update the assign name here (i.e :current_admin)
    |> assign(:current_user, user)
    |> put_flash(:info, message)
    |> redirect(to: target)
  end

  @doc "Failed authentication: neutral flash message (no user enumeration)."
  def failure(conn, activity, reason) do
    message =
      case {activity, reason} do
        {_,
         %AshAuthentication.Errors.AuthenticationFailed{
           caused_by: %Ash.Error.Forbidden{
             errors: [%AshAuthentication.Errors.CannotConfirmUnconfirmedUser{}]
           }
         }} ->
          """
          You have already signed in another way, but have not confirmed your account.
          You can confirm your account using the link we sent to you, or by resetting your password.
          """

        {_,
         %AshAuthentication.Errors.AuthenticationFailed{
           caused_by: %AshAuthentication.Errors.ConfirmationRequired{}
         }} ->
          """
          An account with this email already exists. We've sent a link to that
          address - confirm it to finish linking this provider to your account.
          """

        {{:password, _}, _} ->
          "Incorrect email or password"

        {{:magic_link, _}, _} ->
          "Invalid or expired sign-in link"

        _ ->
          "Authentication failed"
      end

    conn
    |> put_flash(:error, message)
    |> redirect(to: ~p"/sign-in")
  end

  @doc "Signs the user out and clears the session."
  def sign_out(conn, _params) do
    target = return_to(conn)

    conn
    |> clear_session(:accela_imageboard)
    |> put_flash(:info, "You are now signed out")
    |> redirect(to: target)
  end

  # The session value is only ever written by this application today, but a
  # redirect target read back from the session is an open redirect waiting for
  # someone to start populating it from params: allow local paths only.
  defp return_to(conn) do
    case get_session(conn, :return_to) do
      path when is_binary(path) -> if Regex.match?(@local_path, path), do: path, else: ~p"/"
      _absent_or_invalid -> ~p"/"
    end
  end
end
