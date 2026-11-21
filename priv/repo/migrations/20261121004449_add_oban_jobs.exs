defmodule AccelaImageboard.Repo.Migrations.AddObanJobs do
  @moduledoc """
  Creates Oban's own schema (`oban_jobs` plus its functions/triggers).

  Oban ships no SQL files in `deps/oban/priv` — the schema is Ecto migration
  code in `Oban.Migration`, and `Oban.Migrations.up/1` applies every version in
  order. Keeping it as a normal migration (instead of calling it from seeds or
  a task) means one `mix ecto.migrate` / `mix ash.migrate` prepares dev, test
  and production, and the `oban_jobs` rows roll back with the rest of a
  migration.

  Note: Oban verifies at boot (any `testing` mode other than `:disabled`) that
  this migration has run, so the test database needs it too — it runs as part
  of the `test` alias' `ash.setup`.
  """

  use Ecto.Migration

  def up, do: Oban.Migrations.up()

  # Rolls Oban's schema back to its initial version, i.e. drops what `up/0`
  # created (docs: "`Oban.Migration.down()` runs all migrations from the current
  # version down to the first").
  def down, do: Oban.Migrations.down()
end
