defmodule AccelaImageboard.Moderation.Changes.ExistingPost do
  @moduledoc """
  Fails closed when a report's `post_id` does not resolve to a live post.

  `Report.create` is open to anonymous visitors, so `post_id` is untrusted
  input: without this check a reporter could store arbitrary ids (or probe
  them) and staff would triage reports about posts that never existed
  (audit F-17). The lookup uses the primary Post read action, which already
  excludes moderated content, so reporting a removed post is refused too.
  """

  use Ash.Resource.Change

  alias AccelaImageboard.Boards.Post

  @impl Ash.Resource.Change
  def change(changeset, opts, _context) do
    attribute = Keyword.get(opts, :attr, :post_id)

    Ash.Changeset.before_action(changeset, fn changeset ->
      case Ash.Changeset.get_attribute(changeset, attribute) do
        nil ->
          Ash.Changeset.add_error(changeset,
            field: attribute,
            message: "must refer to an existing post"
          )

        post_id ->
          ensure_post_exists(changeset, attribute, post_id)
      end
    end)
  end

  defp ensure_post_exists(changeset, attribute, post_id) do
    case Ash.get(Post, post_id, authorize?: false) do
      {:ok, %Post{}} ->
        changeset

      _missing_or_invalid ->
        Ash.Changeset.add_error(changeset,
          field: attribute,
          message: "must refer to an existing post"
        )
    end
  end
end
