defmodule AccelaImageboard.BoardsTest do
  @moduledoc """
  Security invariants for the Boards domain:

  * anonymous posting is allowed on open threads and blocked on locked ones
  * the anonymous identity (keyed IP hash) comes only from server-side
    context, never from user-supplied params
  * active bans block posting (fail closed)
  * board management is staff-only
  * moderated (soft-deleted) posts and hidden boards are invisible on every
    public read path, and reachable only through staff-only actions
  """

  use AccelaImageboard.DataCase, async: true

  alias AccelaImageboard.Accounts.User
  alias AccelaImageboard.Boards
  alias AccelaImageboard.PolicyChecks.Staff

  setup do
    # Unique identity per test so hammer rate-limit buckets don't collide.
    anon = anon_context()
    staff = create_staff_user()

    board = create_board(slug: "g", name: "Technology")
    thread = create_thread(board, subject: "OP thread")

    %{board: board, thread: thread, staff: staff, anon: anon}
  end

  # A record filtered out by the action's filter is simply not found.
  defp refute_readable(result) do
    case result do
      {:ok, nil} ->
        true

      {:error, %Ash.Error.Invalid{errors: errors}} ->
        Enum.any?(errors, &match?(%Ash.Error.Query.NotFound{}, &1))

      {:error, %Ash.Error.Query.NotFound{}} ->
        true

      other ->
        flunk("expected a not-found result, got: #{inspect(other)}")
    end
  end

  # Public list actions are paginated (see `pagination_test.exs`), so a read
  # may come back as a plain list or as a page: accept both, and only look at
  # the rows.
  defp ids(%{results: results}), do: Enum.map(results, & &1.id)
  defp ids(records) when is_list(records), do: Enum.map(records, & &1.id)

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

  describe "moderated posts (audit A1)" do
    test "are excluded from every public read path", %{
      thread: thread,
      staff: staff,
      anon: anon
    } do
      {:ok, visible} = create_post(thread, context: anon, body: "keep me")
      {:ok, removed} = create_post(thread, context: anon, body: "remove me")

      {:ok, moderated} = Ash.update(removed, %{}, action: :moderate, actor: staff)
      assert moderated.deleted_at

      # 1. the primary read action
      public_ids = Boards.Post |> Ash.read!(actor: nil) |> ids()
      assert visible.id in public_ids
      refute moderated.id in public_ids

      # 2. the thread.posts relationship
      loaded = Ash.load!(thread, :posts, actor: nil)
      assert visible.id in ids(loaded.posts)
      refute moderated.id in ids(loaded.posts)

      # 3. a single moderated post cannot be fetched
      assert refute_readable(Ash.get(Boards.Post, moderated.id, actor: nil))

      # 4. the thread aggregates
      reloaded = Ash.load!(thread, [:post_count, :first_post_id, :last_post_id], actor: nil)
      assert reloaded.post_count == 1
      assert reloaded.first_post_id == visible.id
      assert reloaded.last_post_id == visible.id
    end

    test "do not count towards aggregates when they are the only posts", %{
      thread: thread,
      staff: staff,
      anon: anon
    } do
      {:ok, post} = create_post(thread, context: anon)
      {:ok, _moderated} = Ash.update(post, %{}, action: :moderate, actor: staff)

      reloaded = Ash.load!(thread, [:post_count, :first_post_id, :last_post_id], actor: nil)
      assert reloaded.post_count == 0
      assert is_nil(reloaded.first_post_id)
      assert is_nil(reloaded.last_post_id)
    end

    test "are readable by staff through the moderation queue", %{
      thread: thread,
      staff: staff,
      anon: anon
    } do
      {:ok, post} = create_post(thread, context: anon)
      {:ok, moderated} = Ash.update(post, %{}, action: :moderate, actor: staff)

      queue_ids = Boards.Post |> Ash.read!(action: :moderation_queue, actor: staff) |> ids()
      assert moderated.id in queue_ids

      assert {:ok, fetched} =
               Ash.get(Boards.Post, moderated.id, action: :moderation_queue, actor: staff)

      assert fetched.id == moderated.id
    end

    test "the moderation queue is forbidden for anonymous actors", %{anon: anon} do
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.read(Boards.Post, action: :moderation_queue, actor: nil)

      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.read(Boards.Post, action: :moderation_queue, actor: anon)
    end
  end

  describe "hidden boards (audit A2)" do
    test "are excluded from public board reads", %{staff: staff} do
      hidden = create_board(hidden: true)

      refute hidden.id in (Boards.Board |> Ash.read!(actor: nil) |> ids())
      assert refute_readable(Ash.get(Boards.Board, hidden.id, actor: nil))

      # staff can still reach them
      assert {:ok, found} =
               Ash.get(Boards.Board, hidden.id, action: :staff_read, actor: staff)

      assert found.id == hidden.id

      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.read(Boards.Board, action: :staff_read, actor: nil)
    end

    test "their threads are not publicly readable", %{staff: staff} do
      hidden = create_board(hidden: true)
      thread = create_thread(hidden, subject: "secret OP")

      assert refute_readable(Ash.get(Boards.Thread, thread.id, actor: nil))
      refute thread.id in (Boards.Thread |> Ash.read!(actor: nil) |> ids())

      # staff-only read path
      staff_thread_ids = Boards.Thread |> Ash.read!(action: :staff_read, actor: staff) |> ids()
      assert thread.id in staff_thread_ids

      assert {:ok, found} = Ash.get(Boards.Thread, thread.id, action: :staff_read, actor: staff)
      assert found.id == thread.id

      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.read(Boards.Thread, action: :staff_read, actor: nil)
    end

    test "threads of visible boards stay publicly readable", %{thread: thread} do
      assert thread.id in (Boards.Thread |> Ash.read!(actor: nil) |> ids())
      assert {:ok, found} = Ash.get(Boards.Thread, thread.id, actor: nil)
      assert found.id == thread.id
    end
  end

  describe "staff check (audit F-18)" do
    test "rejects a bare map that claims to be staff" do
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.create(Boards.Board, %{slug: "forged", name: "Forged"},
                 actor: %{is_staff: true}
               )
    end

    test "matches only real staff user structs", %{staff: staff} do
      assert Staff.match?(staff, %{}, [])

      refute Staff.match?(%User{is_staff: false}, %{}, [])
      refute Staff.match?(%User{}, %{}, [])
      refute Staff.match?(%{is_staff: true}, %{}, [])
      refute Staff.match?(nil, %{}, [])
    end
  end
end
