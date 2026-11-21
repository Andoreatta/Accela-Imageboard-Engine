defmodule AccelaImageboard.Security.PosterIdentityTest do
  @moduledoc """
  The poster identity set that bans can match against.

  A ban must survive cheap evasion. Rotating the exact IP (VPN, mobile
  roaming, Tor) changes the exact hash but not the network prefix; clearing
  cookies does nothing about the IP. Together — exact hash, network-prefix
  hash and a server-issued session token hash — they are the identifiers a
  ban row can target, and all of them are keyed HMACs: no raw IP is ever
  computed at rest.
  """

  use AccelaImageboard.DataCase, async: true

  alias AccelaImageboard.Security.IpHash
  alias AccelaImageboard.Security.TokenHash

  describe "IpHash.net/1 (network-prefix identity)" do
    test "an IPv4 /24 is stable across the changing octet" do
      assert {:ipv4_24, net_a} = IpHash.net("203.0.113.7")
      assert {:ipv4_24, net_b} = IpHash.net("203.0.113.200")
      assert net_a == net_b
    end

    test "a different IPv4 /24 nets a different hash" do
      assert {:ipv4_24, net_a} = IpHash.net("203.0.113.7")
      assert {:ipv4_24, net_b} = IpHash.net("203.0.114.7")
      refute net_a == net_b
    end

    test "an IPv6 /64 is stable across host-suffix churn" do
      assert {:ipv6_64, net_a} = IpHash.net("2001:db8:1:2::dead")
      assert {:ipv6_64, net_b} = IpHash.net("2001:db8:1:2:ffff::1")
      assert net_a == net_b
    end

    test "a different IPv6 /64 nets a different hash" do
      assert {:ipv6_64, net_a} = IpHash.net("2001:db8:1:2::1")
      assert {:ipv6_64, net_b} = IpHash.net("2001:db8:1:3::1")
      refute net_a == net_b
    end

    test "the net hash never equals the exact hash of any address" do
      # Domain separation: prefix hashes are HMACs of distinct messages, so a
      # ban row can never be confused about which identifier it targets.
      assert {:ipv4_24, net} = IpHash.net("203.0.113.7")
      refute net == IpHash.hash("203.0.113.7")
      # Also not the exact hash of the prefix's network address itself.
      refute net == IpHash.hash("203.0.113.0")
    end

    test "IPv4-mapped IPv6 notation hashes like the plain IPv4 address" do
      assert {:ipv4_24, mapped} = IpHash.net("::ffff:203.0.113.7")
      assert {:ipv4_24, plain} = IpHash.net("203.0.113.7")
      assert mapped == plain
    end

    test "accepts IP tuples like hash/1 does" do
      assert IpHash.net({203, 0, 113, 7}) == IpHash.net("203.0.113.7")
      # `::ffff:203.0.113.7` written as its 8-tuple: 0xCB00 = 203.0, 0x7107 = 113.7.
      assert IpHash.net({0, 0, 0, 0, 0, 0xFFFF, 0xCB00, 0x7107}) == IpHash.net("203.0.113.7")
    end

    test "refuses invalid input" do
      assert_raise ArgumentError, fn -> IpHash.net("not-an-ip") end
      assert_raise ArgumentError, fn -> IpHash.net(:nope) end
    end
  end

  describe "TokenHash (anonymous session token)" do
    test "hashing is stable and distinct per token" do
      a1 = TokenHash.hash("token-a")
      a2 = TokenHash.hash("token-a")

      assert is_binary(a1) and byte_size(a1) == 64
      assert a1 == a2
      refute a1 == TokenHash.hash("token-b")
    end

    test "a token hash never collides with an IP hash domain" do
      # Same pepper, different message domain: an IP cannot be made to inherit
      # another poster's token identity (or vice versa).
      refute TokenHash.hash("203.0.113.7") == IpHash.hash("203.0.113.7")
    end

    test "verification is constant-time and exact" do
      token = TokenHash.generate()

      assert TokenHash.valid?(TokenHash.hash(token), token)
      refute TokenHash.valid?(TokenHash.hash(token), TokenHash.generate())
    end

    test "generate/0 yields long, unpredictable, unguessable tokens" do
      a = TokenHash.generate()
      b = TokenHash.generate()

      assert is_binary(a) and byte_size(a) >= 32
      assert a != b
      refute String.contains?(a, " ")
    end

    test "refuses empty or non-binary tokens (fail closed)" do
      assert_raise ArgumentError, fn -> TokenHash.hash("") end
      assert_raise ArgumentError, fn -> TokenHash.hash(nil) end
      assert TokenHash.valid?("whatever", nil) == false
    end
  end
end
