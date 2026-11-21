# Seeds — the *only* way staff accounts come into existence.
#
#     mix run priv/repo/seeds.exs
#
# The script is idempotent: running it again never duplicates a user or a board.
#
# ## Staff provisioning
#
# Staff can no longer self-register (`:register_with_password` is forbidden for
# anonymous/non-staff actors — see `AccelaImageboard.Accounts.User`), so an
# operator provisions them here, at the data layer, with `authorize?: false`
# exactly like a seed script should.
#
# The password never has a default: set it in the environment.
#
#     $env:SEED_ADMIN_PASSWORD = "..."      # PowerShell
#     export SEED_ADMIN_PASSWORD="..."      # POSIX
#     SEED_ADMIN_EMAIL / SEED_ADMIN_EMAIL — optional, defaults below.
#
# Without `SEED_ADMIN_PASSWORD` the admin is skipped with a loud warning (an
# account with a weak, committed default password would be worse than no
# account at all). Re-run the script with the variable set to create it.
#
# ## Boards
#
# The starter boards are created with `authorize?: false` for the same reason:
# board management is staff-only, and seeds run without an actor.
#
# ## Background jobs (Oban)
#
# The `oban_jobs` table(s) are created by a regular migration in
# `priv/repo/migrations/*_add_oban_jobs.exs` (`Oban.Migrations.up/1`), so
# `mix ecto.migrate` (or `mix ash.migrate`) is all a fresh database needs.
# Note: current Oban versions ship no SQL files under `deps/oban/priv`; the
# schema lives in `Oban.Migration` as Ecto migration code. If a deployment ever
# has to bootstrap Oban outside of `mix ecto.migrate`, run:
#
#     mix run -e "Oban.Migration.up()"
#
# (that is the `Oban.Migrator`-style escape hatch; `up/1` is idempotent).

alias AccelaImageboard.Accounts.User
alias AccelaImageboard.Boards.Board

defmodule AccelaImageboard.Seeds do
  @moduledoc false

  @admin_email_key "SEED_ADMIN_EMAIL"
  @default_admin_email "admin@accela.invalid"
  @password_key "SEED_ADMIN_PASSWORD"

  @starter_boards [
    %{
      slug: "g",
      name: "Technology",
      description: "Technology, hardware, software and the internet.",
      rules: "No personal information. No coordinated harassment. Cite your sources."
    },
    %{
      slug: "meta",
      name: "Meta",
      description: "Discussion about this imageboard itself.",
      rules: "Site feedback, moderation questions, bug reports."
    }
  ]

  @doc """
  Runs the whole seed set: the operator-provisioned admin, then the boards.
  """
  def run do
    seed_admin()
    seed_boards()
  end

  @doc """
  Provisions the staff admin account from `SEED_ADMIN_EMAIL` /
  `SEED_ADMIN_PASSWORD`, confirming it and setting `is_staff: true`.

  Returns `{:ok, user}`, `:skipped`, or `{:error, reason}`.
  """
  def seed_admin do
    email = System.get_env(@admin_email_key) || @default_admin_email

    case System.get_env(@password_key) do
      password when is_binary(password) and byte_size(password) > 0 ->
        provision_admin(email, password)

      _unset ->
        IO.puts("""
        [seeds] SKIPPED staff admin #{email}: #{@password_key} is not set.

                An operator provisions staff accounts — there is no
                self-registration. Set #{@password_key} and re-run this script:

                    $env:#{@password_key} = "<strong password>"; mix run priv/repo/seeds.exs
        """)

        :skipped
    end
  end

  @doc """
  Idempotently creates the starter boards. Returns `{:ok, boards}`.
  """
  def seed_boards do
    boards =
      Enum.map(@starter_boards, fn attrs ->
        case find_board(attrs.slug) do
          %Board{} = existing ->
            IO.puts("[seeds] board /#{attrs.slug}/ already exists (kept as is)")
            existing

          nil ->
            {:ok, board} = Ash.create(Board, attrs, authorize?: false)
            IO.puts("[seeds] created board /#{attrs.slug}/ (#{attrs.name})")
            board
        end
      end)

    {:ok, boards}
  end

  defp provision_admin(email, password) do
    case find_user(email) do
      %User{} = existing ->
        {:ok, user} = make_staff(existing)
        IO.puts("[seeds] staff admin #{user.email} already exists (ensured staff/confirmed)")
        {:ok, user}

      nil ->
        {:ok, user} = create_user(email, password)
        {:ok, staff} = make_staff(user)
        IO.puts("[seeds] created staff admin #{staff.email}")
        {:ok, staff}
    end
  end

  # The registration action is forbidden for anonymous/non-staff actors; an
  # operator seeds the account with `authorize?: false`, then flips the staff
  # flag the same way.
  defp create_user(email, password) do
    Ash.create(
      User,
      %{email: email, password: password, password_confirmation: password},
      action: :register_with_password,
      authorize?: false
    )
  end

  # An operator-provisioned account is confirmed by definition (no email round
  # trip for a seeded admin), and staff.
  defp make_staff(%User{} = user) do
    user
    |> Ash.Changeset.for_update(:set_staff_flag, %{is_staff: true}, authorize?: false)
    |> Ash.Changeset.force_change_attribute(
      :confirmed_at,
      user.confirmed_at || DateTime.utc_now()
    )
    |> Ash.update()
  end

  # Identity lookup, not a filtered read: the board read actions hide hidden
  # boards, and seeds must be able to see them to stay idempotent.
  defp find_board(slug) do
    case Ash.get(Board, %{slug: slug}, action: :staff_read, authorize?: false) do
      {:ok, %Board{} = board} -> board
      _not_found -> nil
    end
  end

  defp find_user(email) do
    case Ash.get(User, %{email: email}, authorize?: false) do
      {:ok, %User{} = user} -> user
      _not_found -> nil
    end
  end
end

AccelaImageboard.Seeds.run()
