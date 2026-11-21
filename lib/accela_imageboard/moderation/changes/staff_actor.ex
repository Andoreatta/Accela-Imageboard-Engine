defmodule AccelaImageboard.Moderation.Changes.StaffActor do
  @moduledoc """
  Sets a `belongs_to` foreign key attribute (by default `:staff_id`) from the
  authenticated actor, never from params.

  Attribution must not be forgeable: a staff member cannot pass another staff
  member's id and have the action logged under that name (audit F-12), so the
  attribute is force-changed from `context.actor` and rejected when the actor
  is missing.

  Usage:

      create :log do
        change AccelaImageboard.Moderation.Changes.StaffActor
      end
  """

  use Ash.Resource.Change

  alias AccelaImageboard.Accounts.User

  @impl Ash.Resource.Change
  def init(opts), do: {:ok, Keyword.put_new(opts, :attr, :staff_id)}

  @impl Ash.Resource.Change
  def change(changeset, opts, context) do
    attribute = opts[:attr]

    case actor_id(context.actor) do
      nil ->
        Ash.Changeset.add_error(changeset,
          field: attribute,
          message: "must be derived from an authenticated actor, never from params"
        )

      actor_id ->
        Ash.Changeset.force_change_attribute(changeset, attribute, actor_id)
    end
  end

  defp actor_id(%User{id: id}) when not is_nil(id), do: id
  defp actor_id(_actor), do: nil
end
