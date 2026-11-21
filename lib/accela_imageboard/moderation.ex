defmodule AccelaImageboard.Moderation do
  @moduledoc """
  Staff moderation domain: bans, reports and the moderation audit log.

  Nothing here is public: every resource requires a staff actor
  (`AccelaImageboard.PolicyChecks.Staff`). Anonymous enforcement data
  (bans keyed by hashed IP) is written by staff actions only.
  """

  use Ash.Domain, otp_app: :accela_imageboard

  resources do
    resource AccelaImageboard.Moderation.Ban
    resource AccelaImageboard.Moderation.Report
    resource AccelaImageboard.Moderation.ActionLog
  end
end
