defmodule AccelaImageboard.PostingFlowTest do
  @moduledoc """
  Imageboard posting semantics of the Boards domain:

  * a thread is born with its opening post (OP): the body comes from
    `Thread.create`'s `:body` argument, the identity from the anonymous
    context, and `is_op` is forced server-side;
  * one human action costs one rate-limit token (`thread_create`, never also
    `post_create`);
  * an anonymous reply bumps its thread through the policy path;
  * a refused bump never discards the reply, and a locked/archived thread never
    bumps;
  * the OP cannot be created or forged outside the thread-creation flow.
  """

  use AccelaImageboard.DataCase, async: true

  import Ash.Expr

  require Ash.Query

  alias AccelaImageboard.Boards.Post
  alias AccelaImageboard.Boards.Thread
  alias AccelaImageboard.Moderation.Ban
  alias AccelaImageboard.RateLimits

  setup do
    unique = System.unique_integer([:positive, :monotonic])

    %{
      board: create_board(slug: "pf#{unique}", name: "Posting flow"),
      staff: create_staff_user()
    }
  end

  # Opens a thread the way a visitor does â€” through policies, with an actor-less
  # anonymous context.
  defp open_thread(board, context, attrs \\ %{}) do
    params = Map.merge(%{board_id: board.id, subject: "A thread", body: "opening post"}, attrs)

    Ash.create(Thread, params, context: context, actor: nil)
  end

  defp visible_posts(thread) do
    thread |> Ash.load!(:posts, actor: nil) |> Map.fetch!(:posts)
  end

  defp board_threads(board) do
    Thread
    |> Ash.Query.for_read(:read)
    |> Ash.Query.filter(expr(board_id == ^board.id))
    |> Ash.read!(actor: nil)
    |> Map.fetch!(:results)
  end

  describe "thread creation and its opening post" do
    test "creates the thread with exactly one OP post", %{board: board} do
      anon = anon_context("op")

      assert {:ok, thread} = open_thread(board, anon, %{subject: "Hello", body: "first!"})

      assert [op] = visible_posts(thread)
      assert op.is_op
      assert op.body == "first!"
      # The identity is the anonymous context's keyed hash, never a parameter.
      assert op.poster_hash == anon[:anonymous][:ip_hash]

      loaded = Ash.load!(thread, [:post_count, :first_post_id, :last_post_id], actor: nil)
      assert loaded.post_count == 1
      assert loaded.first_post_id == op.id
      assert loaded.last_post_id == op.id
    end

    test "costs one rate-limit token â€” the OP does not burn a post_create token", %{
      board: board
    } do
      anon = anon_context("bucket")
      hash = anon[:anonymous][:ip_hash]

      assert {:ok, _thread} = open_thread(board, anon)

      # One hit from the create, one from this probe.
      assert {:allow, 2} = RateLimits.allowed?(:thread_create, hash)
      # Never touched by the OP: this probe is the first hit.
      assert {:allow, 1} = RateLimits.allowed?(:post_create, hash)
    end

    test "rejects an empty body and creates nothing", %{board: board} do
      anon = anon_context("empty")

      assert {:error, error} = open_thread(board, anon, %{body: ""})
      assert String.contains?(Ash.Error.error_descriptions(error), "body")

      assert {:error, missing} =
               Ash.create(Thread, %{board_id: board.id, subject: "No body"},
                 context: anon,
                 actor: nil
               )

      assert String.contains?(Ash.Error.error_descriptions(missing), "body")

      assert {:ok, %{results: []}} =
               Thread
               |> Ash.Query.for_read(:read)
               |> Ash.Query.filter(expr(board_id == ^board.id))
               |> Ash.read(actor: nil)
    end

    test "requires an attributable poster identity", %{board: board} do
      assert {:error, error} =
               Ash.create(Thread, %{board_id: board.id, subject: "Anon", body: "hi"}, actor: nil)

      assert String.contains?(Ash.Error.error_descriptions(error), "identity")
    end

    test "a banned poster cannot create a thread", %{board: board, staff: staff} do
      anon = anon_context("banned")

      assert {:ok, _ban} =
               Ash.create(
                 Ban,
                 %{
                   poster_hash: anon[:anonymous][:ip_hash],
                   reason: "spam",
                   expires_at: nil,
                   issued_by_id: staff.id
                 },
                 authorize?: false
               )

      assert {:error, error} = open_thread(board, anon)
      assert String.contains?(Ash.Error.error_descriptions(error), "banned")

      assert {:ok, %{results: []}} =
               Thread
               |> Ash.Query.for_read(:read)
               |> Ash.Query.filter(expr(board_id == ^board.id))
               |> Ash.read(actor: nil)
    end

    test "a reply is never an OP", %{board: board} do
      anon = anon_context("reply")
      assert {:ok, thread} = open_thread(board, anon)

      # `is_op` is not accepted input on the public reply action.
      assert {:error, error} =
               Ash.create(Post, %{thread_id: thread.id, body: "hi", is_op: true},
                 context: anon,
                 actor: nil
               )

      assert String.contains?(Ash.Error.error_descriptions(error), "is_op")

      assert {:ok, reply} =
               Ash.create(Post, %{thread_id: thread.id, body: "hi"}, context: anon, actor: nil)

      refute reply.is_op
    end

    test "the OP cannot be created outside the thread-creation flow", %{board: board} do
      anon = anon_context("fake-op")
      assert {:ok, thread} = open_thread(board, anon)

      # No marker: a standalone call is refused.
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.create(Post, %{thread_id: thread.id, body: "fake op"},
                 action: :create_op,
                 context: anon,
                 actor: nil
               )

      # A marker minted for another thread cannot be replayed on this one.
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.create(Post, %{thread_id: thread.id, body: "fake op"},
                 action: :create_op,
                 actor: nil,
                 context: %{
                   anonymous: %{ip_hash: anon[:anonymous][:ip_hash]},
                   posting_flow: %{op: true, thread_id: "some-other-thread"}
                 }
               )

      # No staff branch either: staff OPs come from the thread flow as well.
      assert [op] = visible_posts(thread)
      assert op.body == "opening post"
    end
  end

  describe "reply bump" do
    test "an anonymous reply bumps its thread to the top of the board", %{board: board} do
      anon = anon_context("bump")

      assert {:ok, older} = open_thread(board, anon, %{subject: "older"})
      assert {:ok, newer} = open_thread(board, anon, %{subject: "newer"})

      # `newer` was created last, so it leads the board.
      assert [first | _] = board_threads(board)
      assert first.id == newer.id

      bumped_before = Ash.get!(Thread, older.id, actor: nil).bumped_at

      assert {:ok, _reply} =
               Ash.create(Post, %{thread_id: older.id, body: "bump"}, context: anon, actor: nil)

      reloaded = Ash.get!(Thread, older.id, actor: nil)
      assert DateTime.compare(reloaded.bumped_at, bumped_before) == :gt

      assert [first_after | _] = board_threads(board)
      assert first_after.id == older.id
    end

    test "a locked thread is not bumped, and the staff reply is still stored", %{
      board: board,
      staff: staff
    } do
      anon = anon_context("locked")
      assert {:ok, thread} = open_thread(board, anon)

      assert {:ok, locked} =
               Ash.update(thread, %{locked: true}, action: :staff_update, actor: staff)

      # Anonymous posting into a locked thread is refused outrightâ€¦
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.create(Post, %{thread_id: locked.id, body: "too late"},
                 context: anon,
                 actor: nil
               )

      # â€¦while staff may still post there. The bump refuses (locked) and the
      # reply survives: the create is not rolled back by a refused bump.
      assert {:ok, reply} =
               Ash.create(Post, %{thread_id: locked.id, body: "late"},
                 context: anon,
                 actor: staff
               )

      assert Ash.get!(Post, reply.id, actor: nil).id == reply.id

      assert Ash.get!(Thread, thread.id, actor: nil).bumped_at == locked.bumped_at
    end

    test "an archived thread is not bumped either", %{board: board, staff: staff} do
      anon = anon_context("archived")
      assert {:ok, thread} = open_thread(board, anon)

      assert {:ok, archived} =
               Ash.update(thread, %{archived: true}, action: :staff_update, actor: staff)

      assert {:ok, reply} =
               Ash.create(Post, %{thread_id: archived.id, body: "late"},
                 context: anon,
                 actor: staff
               )

      assert Ash.get!(Post, reply.id, actor: nil).id == reply.id

      assert Ash.get!(Thread, thread.id, actor: nil).bumped_at == archived.bumped_at
    end

    test "staff can still bump a thread on purpose", %{board: board, staff: staff} do
      assert {:ok, thread} = open_thread(board, anon_context("staff-bump"))

      assert {:ok, bumped} = Ash.update(thread, %{}, action: :post_bump, actor: staff)
      assert DateTime.compare(bumped.bumped_at, thread.bumped_at) == :gt
    end

    test "an anonymous actor cannot bump a thread directly", %{board: board} do
      assert {:ok, thread} = open_thread(board, anon_context("no-bump"))

      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.update(thread, %{}, action: :post_bump, actor: nil)
    end
  end
end
