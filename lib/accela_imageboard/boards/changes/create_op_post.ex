defmodule AccelaImageboard.Boards.Changes.CreateOpPost do
  @moduledoc """
  Creates the opening post (OP) of a thread that was just created.

  A thread is never born empty. `Thread.create` takes a `:body` argument that is
  stored on the thread's first post — not on the thread — and this change turns
  it into a real `Post` row with `is_op == true`. The hook is an
  `after_action`, which Ash runs inside the same database transaction as the
  thread insert, so a thread whose OP cannot be created (missing identity,
  banned poster, closed board) is rolled back as a whole: the repository never
  holds a thread without its OP.

  ## Identity and server-side markers

  The OP inherits the anonymous identity of the thread-creation call
  (`context[:anonymous][:ip_hash]`, consumed by
  `AccelaImageboard.Boards.Changes.SetPosterHash`) and carries the
  `posting_flow: %{op: true, thread_id: ...}` marker that
  `AccelaImageboard.Boards.Checks.OpPostFlow` requires. `is_op` is set by the
  action's own change, never accepted from input, and the `:create_op` action is
  only reachable with that marker — a client can neither create an OP directly
  nor forge one.

  ## Which rate-limit bucket burns

  One human action costs one token. `Thread.create` charges `:thread_create`,
  and the OP is created through `Post`'s internal `:create_op` action, which
  deliberately runs **no** rate-limit change — so posting a new thread does not
  also burn a `post_create` token (the naive "just call `Post.create` for the
  OP" would charge both for one click). The OP does run the identity and ban
  checks; `BannedPoster` runs twice per thread creation (once for the thread,
  once for the post) because bans are not a budget and the post is the thing
  that lands in the database.
  """

  use Ash.Resource.Change

  alias AccelaImageboard.Boards.Post

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.after_action(changeset, fn changeset, thread ->
      case create_op(changeset, thread) do
        {:ok, _op} -> {:ok, thread}
        {:error, error} -> {:error, error}
      end
    end)
  end

  defp create_op(changeset, thread) do
    Ash.create(Post, op_params(changeset, thread), op_opts(changeset, thread))
  end

  defp op_params(changeset, thread) do
    %{thread_id: thread.id, body: Ash.Changeset.get_argument(changeset, :body)}
    |> put_present(:name, Ash.Changeset.get_attribute(changeset, :name))
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  defp op_opts(changeset, thread) do
    [
      action: :create_op,
      context: %{
        anonymous: get_in(changeset.context || %{}, [:anonymous]),
        posting_flow: %{op: true, thread_id: thread.id}
      }
    ]
    |> copy_authorize?(changeset)
  end

  # A caller that runs without authorization (operator tooling, seeds, fixtures)
  # keeps doing so for the nested write; anything that goes through policies
  # keeps going through policies.
  defp copy_authorize?(opts, changeset) do
    case changeset.context[:private][:authorize?] do
      authorize? when is_boolean(authorize?) -> Keyword.put(opts, :authorize?, authorize?)
      _not_set -> opts
    end
  end
end
