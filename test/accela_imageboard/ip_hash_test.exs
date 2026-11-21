defmodule AccelaImageboard.IpHashTest do
  @moduledoc """
  The anonymous identity primitive: keyed HMAC of the client IP.
  """

  use ExUnit.Case, async: true

  alias AccelaImageboard.Security.IpHash

  test "same IP always maps to the same poster hash" do
    assert IpHash.hash({127, 0, 0, 1}) == IpHash.hash("127.0.0.1")
    assert IpHash.hash({192, 168, 0, 10}) == IpHash.hash({192, 168, 0, 10})
  end

  test "different IPs map to different hashes" do
    assert IpHash.hash("127.0.0.1") != IpHash.hash("127.0.0.2")
  end

  test "hashes are not derivable from the raw IP (no shared prefix leaks)" do
    a = IpHash.hash("127.0.0.1")
    b = IpHash.hash("127.0.0.2")
    assert String.length(a) == 64
    refute String.starts_with?(a, String.slice(b, 0, 2))
  end

  test "verify?/2 matches the hashed identity" do
    hash = IpHash.hash("203.0.113.9")
    assert IpHash.verify?(hash, {203, 0, 113, 9})
    refute IpHash.verify?(hash, "203.0.113.10")
  end

  test "invalid input raises" do
    assert_raise ArgumentError, fn -> IpHash.hash("not-an-ip") end
  end
end
