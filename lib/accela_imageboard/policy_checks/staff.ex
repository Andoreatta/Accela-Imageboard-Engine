defmodule AccelaImageboard.PolicyChecks.Staff do
  @moduledoc """
  Authorizes only staff actors: `AccelaImageboard.Accounts.User` structs with
  `is_staff: true`.

  The match is deliberately a struct pattern, not `%{is_staff: true}`: a bare
  map (or any other term) carrying an `is_staff` key must never satisfy an
  authorization check (audit F-18).
  """

  use Ash.Policy.SimpleCheck

  alias AccelaImageboard.Accounts.User

  @impl Ash.Policy.Check
  def describe(_options) do
    "actor is a staff user (is_staff == true)"
  end

  @impl Ash.Policy.SimpleCheck
  def match?(%User{is_staff: true}, _context, _options), do: true
  def match?(_actor, _context, _options), do: false
end
