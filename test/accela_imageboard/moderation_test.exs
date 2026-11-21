defmodule AccelaImageboard.ModerationTest do
  @moduledoc """
  Moderation invariants (audit F-12/F-13/F-15/F-17):

  * every staff action appends an audit-log entry attributed to the actor
  * `staff_id` is never accepted from params — it always comes from the actor
  * `Ban.read :check` tolerates duplicate poster hashes (no `get?` blow-up)
  * `Report.create` fails closed when the reported post does not exist
  """

  use AccelaImageboard.DataCase, async: true

  alias AccelaImageboard.Moderation.ActionLog
  alias AccelaImageboard.Moderation.Ban
  alias AccelaImageboard.Moderation.Report

  setup do
    staff = create_staff_user()
    board = create_board()
    thread = create_thread(board)
    {:ok, post} = create_post(thread)

    %{staff: staff, board: board, thread: thread, post: post}
  end

  defp audit_entries(staff) do
    Ash.read!(ActionLog, action: :list, actor: staff)
  end

  # `Ash.read/2` takes action arguments through `Ash.Query.for_read/4`.
  defp check_bans(poster_hash, actor) do
    Ban
    |> Ash.Query.for_read(:check, %{poster_hash: poster_hash}, actor: actor)
    |> Ash.read()
  end

  # Ban rows are staff-only in the resource; tests seed them the way an
  # operator tool would. `poster_hash` doubles as the identifier the ban
  # targets — its meaning follows `scope`.
  defp create_ban(staff, attrs) do
    Ash.create(
      Ban,
      Map.merge(%{reason: "spam", expires_at: nil, issued_by_id: staff.id}, attrs),
      actor: staff
    )
  end

  describe "audit log attribution (F-12)" do
    test "staff_id is not accepted from params", %{staff: staff} do
      other_staff = create_staff_user()

      assert {:error, error} =
               Ash.create(
                 ActionLog,
                 %{
                   action: "forged.entry",
                   target_type: "Post",
                   target_id: "any",
                   staff_id: other_staff.id
                 },
                 actor: staff
               )

      assert String.contains?(Ash.Error.error_descriptions(error), "staff_id")
    end

    test "staff_id is derived from the actor", %{staff: staff} do
      assert {:ok, entry} =
               Ash.create(
                 ActionLog,
                 %{action: "manual.note", target_type: "Post", target_id: "any"},
                 actor: staff
               )

      assert entry.staff_id == staff.id
    end

    test "the audit log stays staff-only" do
      assert {:error, %Ash.Error.Forbidden{}} = Ash.read(ActionLog, action: :list, actor: nil)

      assert {:error, error} =
               Ash.create(ActionLog, %{action: "x", target_type: "Post", target_id: "1"})

      assert String.contains?(Ash.Error.error_descriptions(error), "staff")
    end
  end

  describe "audit entries are written by staff actions (F-13)" do
    test "moderating a post", %{staff: staff, post: post} do
      assert {:ok, moderated} = Ash.update(post, %{}, action: :moderate, actor: staff)

      assert [entry] = audit_entries(staff)
      assert entry.action == "post.moderate"
      assert entry.target_type == "Post"
      assert entry.target_id == moderated.id
      assert entry.staff_id == staff.id
    end

    test "banning and lifting a ban", %{staff: staff} do
      assert {:ok, ban} =
               Ash.create(
                 Ban,
                 %{
                   poster_hash: "poster-to-ban",
                   reason: "spam",
                   expires_at: nil,
                   issued_by_id: staff.id
                 },
                 actor: staff
               )

      assert :ok = Ash.destroy(ban, actor: staff)

      actions = staff |> audit_entries() |> Enum.map(& &1.action) |> Enum.sort()
      assert actions == ["ban.ban", "ban.lift"]

      ids = staff |> audit_entries() |> Enum.map(& &1.target_id) |> Enum.uniq()
      assert ids == [ban.id]
    end

    test "staff-updating a thread", %{staff: staff, thread: thread} do
      assert {:ok, updated} =
               Ash.update(thread, %{pinned: true}, action: :staff_update, actor: staff)

      assert [entry] = audit_entries(staff)
      assert entry.action == "thread.staff_update"
      assert entry.target_type == "Thread"
      assert entry.target_id == updated.id
    end

    test "report transitions", %{staff: staff, post: post} do
      assert {:ok, report} =
               Ash.create(
                 Report,
                 %{post_id: post.id, reason: "spam"},
                 context: anon_context("reporter")
               )

      assert {:ok, accepted} = Ash.update(report, %{}, action: :accept, actor: staff)
      assert accepted.state == :accepted

      assert [entry] = audit_entries(staff)
      assert entry.action == "report.accept"
      assert entry.target_type == "Report"
      assert entry.target_id == accepted.id
      assert entry.staff_id == staff.id
    end
  end

  describe "ban checks (F-15)" do
    test "check returns every active ban for a poster hash without raising", %{staff: staff} do
      for _ <- 1..2 do
        assert {:ok, _ban} =
                 Ash.create(
                   Ban,
                   %{
                     poster_hash: "duplicated-poster",
                     reason: "spam",
                     expires_at: nil,
                     issued_by_id: staff.id
                   },
                   actor: staff
                 )
      end

      assert {:ok, bans} = check_bans("duplicated-poster", staff)

      assert Enum.all?(bans, &(&1.poster_hash == "duplicated-poster"))

      assert {:ok, []} = check_bans("nobody", staff)
    end

    test "check ignores expired bans", %{staff: staff} do
      yesterday = DateTime.add(DateTime.utc_now(), -1, :day)

      assert {:ok, _ban} =
               Ash.create(
                 Ban,
                 %{
                   poster_hash: "expired-poster",
                   reason: "spam",
                   expires_at: yesterday,
                   issued_by_id: staff.id
                 },
                 actor: staff
               )

      assert {:ok, []} = check_bans("expired-poster", staff)
    end

    test "bans stay staff-only" do
      assert {:error, %Ash.Error.Forbidden{}} = check_bans("x", nil)
    end
  end

  describe "ban scope (evasion resistance)" do
    test "accepts every identifier scope", %{staff: staff} do
      for scope <- [:exact, :ipv4_24, :ipv6_64, :token] do
        assert {:ok, ban} = create_ban(staff, %{poster_hash: "hash-for-#{scope}", scope: scope})
        assert ban.scope == scope
      end
    end

    test "defaults to :exact, so old bans keep their meaning", %{staff: staff} do
      assert {:ok, ban} = create_ban(staff, %{poster_hash: "hash-without-scope"})
      assert ban.scope == :exact
    end

    test "rejects an unknown scope", %{staff: staff} do
      assert {:error, error} =
               create_ban(staff, %{poster_hash: "hash-with-bad-scope", scope: :wildcard})

      assert String.contains?(Ash.Error.error_descriptions(error), "scope")
    end
  end

  describe "report creation (F-17)" do
    test "fails closed for a post that does not exist", %{staff: staff} do
      assert {:error, error} =
               Ash.create(
                 Report,
                 %{post_id: Ash.UUID.generate(), reason: "spam"},
                 context: anon_context("reporter")
               )

      assert String.contains?(Ash.Error.error_descriptions(error), "post")
      assert audit_entries(staff) == []
    end

    test "fails closed for a moderated post", %{staff: staff, post: post} do
      assert {:ok, moderated} = Ash.update(post, %{}, action: :moderate, actor: staff)

      assert {:error, error} =
               Ash.create(
                 Report,
                 %{post_id: moderated.id, reason: "spam"},
                 context: anon_context("reporter")
               )

      assert String.contains?(Ash.Error.error_descriptions(error), "post")
    end

    test "is accepted for a live post", %{staff: staff, post: post} do
      assert {:ok, report} =
               Ash.create(
                 Report,
                 %{post_id: post.id, reason: "spam"},
                 context: anon_context("reporter")
               )

      assert report.post_id == post.id
      assert report.reporter_hash =~ "reporter-"
      assert {:ok, [_]} = Ash.read(Report, actor: staff)
    end
  end
end
