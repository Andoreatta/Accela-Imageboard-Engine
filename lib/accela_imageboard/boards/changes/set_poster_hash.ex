defmodule AccelaImageboard.Boards.Changes.SetPosterHash do
  @moduledoc """
  Stores the anonymous poster's keyed IP hash as the resource's poster
  identity attribute.

  The web layer puts the hash in the action's context:
  `Ash.create(..., context: %{anonymous: %{ip_hash: hash}})`. Accepting the
  poster hash from user input would allow identity spoofing, so it is NEVER
  accepted from parameters — only from this server-computed context.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def init(opts), do: {:ok, Keyword.put_new(opts, :attr, :poster_hash)}

  @impl Ash.Resource.Change
  def change(changeset, opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      case changeset.context[:anonymous][:ip_hash] do
        %{"hash" => _} = map ->
          Ash.Changeset.force_change_attribute(changeset, opts[:attr], map["hash"])

        hash when is_binary(hash) and byte_size(hash) > 0 ->
          Ash.Changeset.force_change_attribute(changeset, opts[:attr], hash)

        _ ->
          Ash.Changeset.add_error(changeset,
            field: opts[:attr],
            message: "missing anonymous identity — refusing to attribute this post"
          )
      end
    end)
  end
end
