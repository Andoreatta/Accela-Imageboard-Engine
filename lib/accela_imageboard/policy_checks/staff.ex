defmodule AccelaImageboard.PolicyChecks.Staff do
  @moduledoc """
  Authorizes only staff actors (`AccelaImageboard.Accounts.User` with
  `is_staff: true`).
  """

  use Ash.Policy.SimpleCheck

  @impl Ash.Policy.Check
  def describe(_options) do
    "actor.is_staff == true"
  end

  @impl Ash.Policy.SimpleCheck
  def match?(%{is_staff: true}, _context, _options), do: true
  def match?(_actor, _context, _options), do: false
end
