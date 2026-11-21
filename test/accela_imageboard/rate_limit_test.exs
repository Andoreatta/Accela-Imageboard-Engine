defmodule AccelaImageboard.RateLimitTest do
  @moduledoc """
  Rate limiting of anonymous actions, keyed by hashed identity.
  """

  use AccelaImageboard.DataCase, async: false

  alias AccelaImageboard.Boards

  setup do
    # ETS rate-limit buckets persist across tests, so every test uses fresh
    # identities. Limits come from the application defaults.
    uniq = System.unique_integer([:positive, :monotonic])

    {:ok, board} =
      Ash.create(Boards.Board, %{slug: "rl#{uniq}", name: "Rate Limit"}, authorize?: false)

    {:ok, thread} =
      Ash.create(Boards.Thread, %{board_id: board.id, subject: "OP", body: "opening post"},
        context: %{anonymous: %{ip_hash: "rl-op-#{uniq}"}},
        authorize?: false
      )

    %{thread: thread, uniq: uniq}
  end

  test "allows posts up to the configured limit then denies", %{thread: thread, uniq: uniq} do
    context = %{anonymous: %{ip_hash: "rl-A-#{uniq}"}}

    results =
      for i <- 1..21 do
        Ash.create(Boards.Post, %{thread_id: thread.id, body: "post #{i}"},
          context: context,
          actor: nil
        )
      end

    # Default limit for post_create: 20 per 5 minutes.
    assert length(Enum.filter(results, &match?({:ok, _}, &1))) == 20

    assert Enum.any?(results, fn
             {:error, _} -> true
             _ -> false
           end)
  end

  test "limits are independent per poster", %{thread: thread, uniq: uniq} do
    for i <- 1..20 do
      assert {:ok, _} =
               Ash.create(Boards.Post, %{thread_id: thread.id, body: "a#{i}"},
                 context: %{anonymous: %{ip_hash: "rl-B-#{uniq}"}},
                 actor: nil
               )
    end

    # A different poster has its own bucket and is not affected.
    assert {:ok, _} =
             Ash.create(Boards.Post, %{thread_id: thread.id, body: "hello"},
               context: %{anonymous: %{ip_hash: "rl-C-#{uniq}"}},
               actor: nil
             )
  end
end
