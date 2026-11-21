defmodule AccelaImageboard.DataCase do
  @moduledoc """
  This module defines the setup for tests requiring
  access to the application's data layer.

  You may define functions here to be used as helpers in
  your tests.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use AccelaImageboard.DataCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      alias AccelaImageboard.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import AccelaImageboard.DataCase
    end
  end

  setup tags do
    AccelaImageboard.DataCase.setup_sandbox(tags)
    :ok
  end

  @doc """
  Sets up the sandbox based on the test tags.
  """
  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(AccelaImageboard.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end

  @doc """
  Returns a context map carrying a fresh anonymous poster identity.

  Every call yields a distinct keyed IP hash so hammer rate-limit buckets
  (which live in ETS and survive between tests) never collide.
  """
  def anon_context(prefix \\ "poster") do
    %{anonymous: %{ip_hash: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"}}
  end

  @doc """
  Provisions a staff user the way an operator does: directly at the data
  layer, with `authorize?: false` (staff accounts are never self-registered).
  """
  def create_staff_user(opts \\ []) do
    unique = System.unique_integer([:positive, :monotonic])
    password = Keyword.get(opts, :password, "correct horse battery staple")

    {:ok, user} =
      Ash.create(
        AccelaImageboard.Accounts.User,
        %{
          email: Keyword.get(opts, :email, "staff-#{unique}@accela.invalid"),
          password: password,
          password_confirmation: password
        },
        action: :register_with_password,
        authorize?: false
      )

    {:ok, staff} =
      Ash.update(user, %{is_staff: true}, action: :set_staff_flag, authorize?: false)

    staff
  end

  @doc """
  Creates a board, optionally hidden, bypassing policies (seed/fixture use).
  """
  def create_board(opts \\ []) do
    unique = System.unique_integer([:positive, :monotonic])

    attrs = %{
      slug: Keyword.get(opts, :slug, "b#{unique}"),
      name: Keyword.get(opts, :name, "Board #{unique}")
    }

    {:ok, board} = Ash.create(AccelaImageboard.Boards.Board, attrs, authorize?: false)

    case Keyword.get(opts, :hidden, false) do
      true ->
        {:ok, hidden} =
          Ash.update(board, %{hidden: true},
            action: :update,
            authorize?: false
          )

        hidden

      false ->
        board
    end
  end

  @doc """
  Creates a thread in `board` with a fresh anonymous poster identity.
  """
  def create_thread(board, opts \\ []) do
    {:ok, thread} =
      Ash.create(
        AccelaImageboard.Boards.Thread,
        %{board_id: board.id, subject: Keyword.get(opts, :subject, "OP")},
        context: Keyword.get_lazy(opts, :context, fn -> anon_context("thread") end),
        authorize?: false
      )

    thread
  end

  @doc """
  Creates a post in `thread` as an anonymous visitor (or the given context).
  """
  def create_post(thread, opts \\ []) do
    Ash.create(
      AccelaImageboard.Boards.Post,
      %{thread_id: thread.id, body: Keyword.get(opts, :body, "hello")},
      context: Keyword.get_lazy(opts, :context, fn -> anon_context("post") end),
      actor: Keyword.get(opts, :actor)
    )
  end

  @doc """
  A helper that transforms changeset errors into a map of messages.

      assert {:error, changeset} = Accounts.create_user(%{password: "short"})
      assert "password is too short" in errors_on(changeset).password
      assert %{password: ["password is too short"]} = errors_on(changeset)

  """
  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
