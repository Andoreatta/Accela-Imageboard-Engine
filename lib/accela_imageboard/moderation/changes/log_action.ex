defmodule AccelaImageboard.Moderation.Changes.LogAction do
  @moduledoc """
  Appends an `AccelaImageboard.Moderation.ActionLog` row once a staff action
  has succeeded, attributing it to the acting staff member.

  Before this change the audit trail accepted `staff_id` from params and
  nothing ever wrote to it (audit F-12/F-13). The entry is written by the
  server: the target comes from the affected record, the staff member from
  the action's actor, and only the *names* of the changed attributes are
  recorded (never their values, so no sensitive data is duplicated).

  Usage in a staff action:

      update :moderate do
        change({AccelaImageboard.Moderation.Changes.LogAction,
                action: "post.moderate", target_type: "Post"})
      end

  The write fails the action if the audit row cannot be inserted: an
  unlogged moderation action is not an acceptable outcome. Actions invoked
  without an actor (seeds, `authorize?: false` maintenance scripts) are not
  logged, because there is no staff member to attribute them to.
  """

  use Ash.Resource.Change

  alias AccelaImageboard.Accounts.User
  alias AccelaImageboard.Moderation.ActionLog

  @impl Ash.Resource.Change
  def init(opts) do
    with {:ok, action} <- Keyword.fetch(opts, :action),
         {:ok, target_type} <- Keyword.fetch(opts, :target_type) do
      {:ok,
       opts
       |> Keyword.put(:action, to_string(action))
       |> Keyword.put(:target_type, to_string(target_type))}
    else
      :error ->
        {:error, "expected the :action and :target_type options, got: #{inspect(opts)}"}
    end
  end

  @impl Ash.Resource.Change
  def change(changeset, opts, context) do
    Ash.Changeset.after_action(changeset, fn changeset, result ->
      record(changeset, result, opts, context.actor)
    end)
  end

  defp record(changeset, result, opts, %User{} = actor) do
    attributes = %{
      action: opts[:action],
      target_type: opts[:target_type],
      target_id: target_id(changeset, result),
      detail: changed_attributes(changeset)
    }

    ActionLog
    |> Ash.Changeset.for_create(:log, attributes, actor: actor, authorize?: false)
    |> Ash.create()
    |> case do
      {:ok, _entry} -> {:ok, result}
      {:error, error} -> {:error, error}
    end
  end

  defp record(_changeset, result, _opts, _actor), do: {:ok, result}

  defp target_id(changeset, result) do
    source = if is_map(result) and Map.has_key?(result, :id), do: result, else: changeset.data

    case source do
      %{id: nil} -> "unknown"
      %{id: id} -> to_string(id)
      _other -> "unknown"
    end
  end

  defp changed_attributes(changeset) do
    case changeset.attributes do
      attributes when is_map(attributes) and map_size(attributes) > 0 ->
        %{"changed" => attributes |> Map.keys() |> Enum.map(&to_string/1) |> Enum.sort()}

      _none ->
        nil
    end
  end
end
