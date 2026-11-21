defmodule AccelaImageboard.Boards do
  @moduledoc """
  Public imageboard content: boards, threads, posts and their media.

  Authorization model:
  * reading board content is public (anonymous actor)
  * creating posts/threads is allowed for anonymous actors (whose identity
    is a keyed hash of their IP, see `AccelaImageboard.Security.IpHash`)
  * boards are managed by staff only (`AccelaImageboard.PolicyChecks.Staff`)
  """

  use Ash.Domain, otp_app: :accela_imageboard

  resources do
    resource AccelaImageboard.Boards.Board
    resource AccelaImageboard.Boards.Thread
    resource AccelaImageboard.Boards.Post
    resource AccelaImageboard.Boards.Media
  end
end
