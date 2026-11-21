defmodule AccelaImageboard.ObanTest do
  @moduledoc """
  Oban is wired to the app: engine, repo, queues and schema.

  In test it runs in `:manual` mode (no queues, plugins or stager), so jobs are
  only recorded, never executed behind a test's back. Oban itself verifies at
  boot that its migrations ran for any non-`:disabled` testing mode, so these
  assertions also prove `priv/repo/migrations/*_add_oban_jobs.exs` is applied.
  """

  use AccelaImageboard.DataCase, async: true

  use Oban.Testing, repo: AccelaImageboard.Repo

  test "runs in manual mode on the basic engine, against this app's repo" do
    config = Oban.config()

    assert config.testing == :manual
    assert config.engine == Oban.Engines.Basic
    assert config.repo == AccelaImageboard.Repo
    # Manual mode disables workers so nothing runs concurrently with a test.
    assert config.queues == []
  end

  test "is started from the application environment (supervision tree)" do
    env = Application.get_env(:accela_imageboard, Oban)

    assert Keyword.get(env, :repo) == AccelaImageboard.Repo
    assert Keyword.get(env, :engine) == Oban.Engines.Basic
    assert Keyword.get(env, :testing) == :manual

    # `Oban.config/0` reads the live instance's config, so this only passes if
    # the supervisor actually started Oban.
    assert Oban.config().repo == AccelaImageboard.Repo
  end

  test "Oban's schema is migrated" do
    assert Oban.Migration.migrated_version(repo: AccelaImageboard.Repo) > 0
  end

  test "a job can be enqueued and inspected (media queue is available)" do
    assert {:ok, %Oban.Job{queue: "media"} = job} =
             Oban.Job.new(%{"storage_key" => "test-key"},
               queue: :media,
               worker: "MediaTestWorker"
             )
             |> Oban.insert()

    assert job.state == "available"
    assert_enqueued(worker: "MediaTestWorker", queue: :media)
  end
end
