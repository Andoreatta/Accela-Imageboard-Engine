defmodule AccelaImageboard.Accounts do
  @moduledoc """
  Staff authentication domain: users, sessions, tokens (AshAuthentication).
  """

  use Ash.Domain, otp_app: :accela_imageboard, extensions: [AshAdmin.Domain]

  admin do
    show? true
  end

  resources do
    resource AccelaImageboard.Accounts.Token
    resource AccelaImageboard.Accounts.User
  end
end
