defmodule AccelaImageboard.BanEvasionLogTest do
  @moduledoc """
  The evasion signal: when a ban blocks a poster through the network or token
  identifier only — i.e. the exact hash is not itself banned — that is someone
  who changed address (or arrived with a banned cookie), and it must be visible
  in the logs without ever printing a full hash.

  `async: false` on purpose: `ExUnit.CaptureLog` captures globally, so two
  concurrent captures would collide.
  """

  use AccelaImageboard.DataCase, async: false

  import ExUnit.CaptureLog

  alias AccelaImageboard.Boards
  alias AccelaImageboard.Moderation.Ban
  alias AccelaImageboard.Security.IpHash
  alias AccelaImageboard.Security.TokenHash

  setup do
    staff = create_staff_user()
    board = create_board()
    thread = create_thread(board)

    %{thread: thread, staff: staff}
  end

  defp ban(staff, scope, poster_hash) do
    {:ok, ban} =
      Ash.create(
        Ban,
        %{
          poster_hash: poster_hash,
          scope: scope,
          reason: "spam",
          expires_at: nil,
          issued_by_id: staff.id
        },
        authorize?: false
      )

    ban
  end

  defp refuse(thread, context) do
    assert {:error, error} =
             Ash.create(Boards.Post, %{thread_id: thread.id, body: "hello"},
               context: context,
               actor: nil
             )

    error
  end

  test "a network-only match logs an evasion signal with hash prefixes only", %{
    thread: thread,
    staff: staff
  } do
    {:ipv4_24, net_hash} = IpHash.net("203.0.113.7")
    ban(staff, :ipv4_24, net_hash)

    ip_hash = IpHash.hash("203.0.113.99")
    context = %{anonymous: %{ip_hash: ip_hash, net_scope: :ipv4_24, net_hash: net_hash}}

    log = capture_log(fn -> refuse(thread, context) end)

    assert log =~ "ban evasion signal"
    assert log =~ ":ipv4_24"
    assert log =~ String.slice(net_hash, 0, 12)
    # A full hash would let a log reader fingerprint the poster again.
    refute log =~ net_hash
    refute log =~ ip_hash
  end

  test "a token-only match logs an evasion signal", %{thread: thread, staff: staff} do
    token_hash = TokenHash.hash("visitor-token")
    ban(staff, :token, token_hash)

    {:ipv4_24, net_hash} = IpHash.net("198.51.100.1")

    context = %{
      anonymous: %{
        ip_hash: IpHash.hash("198.51.100.1"),
        net_scope: :ipv4_24,
        net_hash: net_hash,
        token_hash: token_hash
      }
    }

    log = capture_log(fn -> refuse(thread, context) end)

    assert log =~ "ban evasion signal"
    assert log =~ ":token"
    refute log =~ token_hash
  end

  test "an exact match is a plain block, not an evasion signal", %{
    thread: thread,
    staff: staff
  } do
    {:ipv4_24, net_hash} = IpHash.net("192.0.2.44")
    ip_hash = IpHash.hash("192.0.2.44")
    ban(staff, :exact, ip_hash)

    context = %{anonymous: %{ip_hash: ip_hash, net_scope: :ipv4_24, net_hash: net_hash}}

    log = capture_log(fn -> refuse(thread, context) end)

    refute log =~ "ban evasion signal"
  end
end
