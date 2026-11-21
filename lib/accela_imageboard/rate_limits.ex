defmodule AccelaImageboard.RateLimits do
  @moduledoc """
  Application-wide rate limiter (ETS-backed, per-node).

  Anonymous actions are keyed by the poster's keyed IP hash, so limit buckets
  are stable per-IP without ever storing a raw IP.

  Limits are configured per action:

      config :accela_imageboard, :rate_limits,
        thread_create: %{scale: :timer.minutes(10), limit: 5},
        ...

  The limiter must be in the supervision tree (see `application.ex`).
  """

  use Hammer, backend: :ets

  @defaults %{
    thread_create: %{scale: :timer.minutes(10), limit: 5},
    post_create: %{scale: :timer.minutes(5), limit: 20},
    report_create: %{scale: :timer.minutes(15), limit: 10}
  }

  @doc """
  Checks & increments the bucket for `action_key` performed by `subject_hash`.

  Returns `{:allow, count}` or `{:deny, retry_after_ms}`.
  """
  @spec allowed?(atom(), String.t()) ::
          {:allow, non_neg_integer()} | {:deny, non_neg_integer()}
  def allowed?(action_key, subject_hash) do
    limits = Application.get_env(:accela_imageboard, :rate_limits, %{})
    action = Map.get(limits, action_key) || Map.fetch!(@defaults, action_key)

    hit({action_key, subject_hash}, action.scale, action.limit)
  end
end
