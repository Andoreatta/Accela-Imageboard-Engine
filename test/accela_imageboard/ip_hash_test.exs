defmodule AccelaImageboard.IpHashTest do
  @moduledoc """
  The anonymous identity primitive: keyed HMAC of the client IP.

  Representation must not matter (audit F-09): an IPv4-mapped IPv6 address,
  a zone identifier, uppercase hex or an uncompressed form all have to map to
  the same poster hash, otherwise a banned poster evades their ban by simply
  switching representation.
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

  describe "IPv6 representation is normalized (F-09)" do
    test "IPv4-mapped IPv6 hashes like the plain IPv4 address" do
      ipv4 = IpHash.hash("203.0.113.9")

      assert IpHash.hash("::ffff:203.0.113.9") == ipv4
      assert IpHash.hash("::FFFF:203.0.113.9") == ipv4
      assert IpHash.hash("0:0:0:0:0:ffff:cb00:7109") == ipv4
      assert IpHash.hash({0, 0, 0, 0, 0, 0xFFFF, 0xCB00, 0x7109}) == ipv4
    end

    test "a zone identifier is ignored" do
      assert IpHash.hash("fe80::1%eth0") == IpHash.hash("fe80::1")
      assert IpHash.hash("fe80::1%25eth0") == IpHash.hash("fe80::1")
      assert IpHash.hash("FE80::1") == IpHash.hash("fe80::1")
    end

    test "compressed and expanded forms of the same address agree" do
      assert IpHash.hash("2001:db8::1") == IpHash.hash("2001:0db8:0000:0000:0000:0000:0000:0001")
      assert IpHash.hash("2001:DB8::1") == IpHash.hash("2001:db8::1")
      assert IpHash.hash("::1") == IpHash.hash("0:0:0:0:0:0:0:1")
    end

    test "different IPv6 addresses still map to different hashes" do
      assert IpHash.hash("2001:db8::1") != IpHash.hash("2001:db8::2")
      refute IpHash.hash("::ffff:203.0.113.9") == IpHash.hash("203.0.113.10")
    end
  end
end
