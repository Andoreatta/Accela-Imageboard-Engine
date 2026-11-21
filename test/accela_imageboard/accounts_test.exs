defmodule AccelaImageboard.AccountsTest do
  @moduledoc """
  Staff account provisioning invariants (web audit #1, domain half):

  * staff accounts are provisioned by an operator — self-registration is
    forbidden at the domain layer for anonymous and non-staff actors
  * AshAuthentication's own strategy calls still work through the
    `AshAuthentication.Checks.AshAuthenticationInteraction` bypass
  """

  use AccelaImageboard.DataCase, async: true

  alias AccelaImageboard.Accounts.User

  defp registration_params do
    unique = System.unique_integer([:positive, :monotonic])

    %{
      email: "self-registered-#{unique}@accela.invalid",
      password: "correct horse battery staple",
      password_confirmation: "correct horse battery staple"
    }
  end

  test "anonymous actors cannot self-register" do
    assert {:error, %Ash.Error.Forbidden{}} =
             Ash.create(User, registration_params(),
               action: :register_with_password,
               actor: nil
             )
  end

  test "non-staff actors cannot register new accounts" do
    assert {:error, %Ash.Error.Forbidden{}} =
             Ash.create(User, registration_params(),
               action: :register_with_password,
               actor: %{is_staff: false}
             )
  end

  test "AshAuthentication internal interactions are still authorized" do
    strategy = AshAuthentication.Info.strategy!(User, :password)

    assert {:ok, user} =
             AshAuthentication.Strategy.Password.Actions.register(
               strategy,
               registration_params(),
               []
             )

    assert user.email |> to_string() =~ "self-registered-"
    refute user.is_staff
  end

  test "operator provisioning works with authorize?: false" do
    staff = create_staff_user()
    assert staff.is_staff
  end
end
