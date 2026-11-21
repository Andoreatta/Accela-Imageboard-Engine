defmodule AccelaImageboard.BoardsTest do
  @moduledoc """
  Security invariants for the Boards domain:

  * anonymous posting is allowed on open threads and blocked on locked ones
  * the anonymous identity (keyed IP hash) comes only from server-side
    context, never from user-supplied params
  * active bans block posting (fail closed)
  * board management is staff-only
  """

  use AccelaImageboard.DataCase, async: true

  alias AccelaImageboard.Boards

  setup do
    # Unique identity per test so hammer rate-limit buckets don't collide.
    anon = %{anonymous: %{ip_hash: "poster-#{System.unique_integer([:positive])}"}}
    staff = register_staff()

    {:ok, board} =
      Ash.create(Boards.Board, %{slug: "g", name: "Technology"}, authorize?: false)

    {:ok, thread} =
      Ash.create(Boards.Thread, %{board_id: board.id, subject: "OP thread"},
        context: anon,
        authorize?: false
      )

    %{board: board, thread: thread, staff: staff, anon: anon}
  end

  defp register_staff do
    {:ok, user} =
      Ash.create(
        AccelaImageboard.Accounts.User,
        %{
          email: "staff-#{System.unique_integer([:positive])}@accela.invalid",
          password: "correct horse battery staple",
          password_confirmation: "correct horse battery staple"
        },
        action: :register_with_password,
        authorize?: false
      )

    {:ok, staff} =
      Ash.update(user, %{is_staff: true},
        action: :set_staff_flag,
        authorize?: false
      )

    staff
  end

  describe "anonymous posting" do
    test "is allowed on open threads", %{thread: thread, anon: anon} do
      assert {:ok, post} =
               Ash.create(Boards.Post, %{thread_id: thread.id, body: "hello"},
                 context: anon,
                 actor: nil
               )

      assert post.body == "hello"
    end

    test "rejects user-supplied identity params (anti-spoofing)", %{thread: thread, anon: anon} do
      # poster_hash is NEVER accepted input: the server-side context is the
      # only source of anonymous identity.
      assert {:error, error} =
               Ash.create(
                 Boards.Post,
                 %{thread_id: thread.id, body: "hello", poster_hash: "spoofed-identity"},
                 context: anon,
                 actor: nil
               )

      assert String.contains?(Ash.Error.error_descriptions(error), "poster_hash")
    end

    test "is refused when the server cannot attribute an identity", %{thread: thread} do
      assert {:error, error} = Ash.create(Boards.Post, %{thread_id: thread.id, body: "hi"})

      assert String.contains?(Ash.Error.error_descriptions(error), "identity")
    end

    test "is blocked on locked threads", %{thread: thread, staff: staff, anon: anon} do
      {:ok, locked} =
        Ash.update(thread, %{locked: true}, action: :staff_update, actor: staff)

      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.create(Boards.Post, %{thread_id: locked.id, body: "hello"},
                 context: anon,
                 actor: nil
               )
    end
  end

  describe "bans" do
    test "block posting from the banned identity (fail closed)", %{
      thread: thread,
      staff: staff,
      anon: anon
    } do
      {:ok, _ban} =
        Ash.create(
          AccelaImageboard.Moderation.Ban,
          %{
            poster_hash: anon[:anonymous][:ip_hash],
            reason: "spam",
            expires_at: nil,
            issued_by_id: staff.id
          },
          authorize?: false
        )

      assert {:error, error} =
               Ash.create(Boards.Post, %{thread_id: thread.id, body: "hello"},
                 context: anon,
                 actor: nil
               )

      assert String.contains?(Ash.Error.error_descriptions(error), "banned")
    end

    test "do not affect other posters", %{thread: thread, staff: staff, anon: anon} do
      {:ok, _ban} =
        Ash.create(
          AccelaImageboard.Moderation.Ban,
          %{
            poster_hash: "another-poster",
            reason: "spam",
            expires_at: nil,
            issued_by_id: staff.id
          },
          authorize?: false
        )

      assert {:ok, _post} =
               Ash.create(Boards.Post, %{thread_id: thread.id, body: "hello"},
                 context: anon,
                 actor: nil
               )
    end
  end

  describe "staff-only management" do
    test "anonymous actors cannot create boards" do
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.create(Boards.Board, %{slug: "x", name: "X"}, actor: nil)
    end

    test "staff can create boards", %{staff: staff} do
      assert {:ok, board} =
               Ash.create(Boards.Board, %{slug: "meta", name: "Meta"}, actor: staff)

      assert board.slug == "meta"
    end
  end
end
