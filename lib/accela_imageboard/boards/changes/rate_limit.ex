defmodule AccelaImageboard.Boards.Changes.RateLimit do
  @moduledoc """
  Applies an action-level rate limit to anonymous posts, keyed by the poster's
  keyed IP hash (from `changeset.context[:anonymous][:ip_hash]`).

  Usage in a resource action:

      change AccelaImageboard.Boards.Changes.RateLimit, key: :post_create

  Limits and windows come from `AccelaImageboard.RateLimits`.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def init(opts) do
    key = Keyword.fetch!(opts, :key)

    if Map.has_key?(%{thread_create: 1, post_create: 1, report_create: 1}, key) do
      {:ok, Keyword.put(opts, :key, key)}
    else
      {:error, "unknown rate limit key: #{inspect(key)}"}
    end
  end

  @impl Ash.Resource.Change
  def change(changeset, opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      subject =
        get_in(changeset.context, [:anonymous, :ip_hash]) ||
          (changeset.data && changeset.data.id && to_string(changeset.data.id)) ||
          "unknown"

      case AccelaImageboard.RateLimits.allowed?(opts[:key], subject) do
        {:allow, _count} ->
          changeset

        {:deny, retry_ms} ->
          Ash.Changeset.add_error(changeset,
            field: :rate_limit,
            message:
              "too many requests — retry in #{div(retry_ms, 1000) + 1}s" <>
                " (limit for #{opts[:key]})"
          )
      end
    end)
  end
end
