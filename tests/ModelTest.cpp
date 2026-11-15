#include "nip/model/Headers.h"
#include "nip/model/ParsedPacket.h"

#include <gtest/gtest.h>

TEST(HeaderLength, Ipv4CountsWordsOfFourBytes) {
    EXPECT_EQ(nip::ipv4HeaderLengthBytes(5), 20);
    EXPECT_EQ(nip::ipv4HeaderLengthBytes(6), 24);
    EXPECT_EQ(nip::ipv4HeaderLengthBytes(15), 60);
    EXPECT_EQ(nip::kIpv4MinHeaderLength, 20u);
    EXPECT_EQ(nip::kIpv4MaxHeaderLength, 60u);
}

TEST(HeaderLength, TcpDataOffsetCountsWordsOfFourBytes) {
    EXPECT_EQ(nip::tcpHeaderLengthBytes(5), 20);
    EXPECT_EQ(nip::tcpHeaderLengthBytes(8), 32);
    EXPECT_EQ(nip::kTcpMinHeaderLength, 20u);
    EXPECT_EQ(nip::kTcpMaxHeaderLength, 60u);
}

TEST(HeaderLength, FixedHeadersMatchTheOnWireMinimum) {
    EXPECT_EQ(nip::kEthernetHeaderLength, 14u);
    EXPECT_EQ(nip::kUdpHeaderLength, 8u);
    EXPECT_EQ(nip::kIcmpMinHeaderLength, 8u);
    EXPECT_EQ(nip::ethertype::kIpv4, 0x0800);
    EXPECT_EQ(nip::ethertype::kIpv6, 0x86DD);
    EXPECT_EQ(nip::ip_protocol::kIcmp, 1);
    EXPECT_EQ(nip::ip_protocol::kTcp, 6);
    EXPECT_EQ(nip::ip_protocol::kUdp, 17);
}

TEST(IPv4Header, InitialFragmentIsOffsetZero) {
    nip::IPv4Header header;
    EXPECT_TRUE(header.isInitialFragment());

    header.moreFragments = true;
    EXPECT_TRUE(header.isInitialFragment());

    header.fragmentOffset = 1;
    EXPECT_FALSE(header.isInitialFragment());
}

TEST(TcpHeader, ReportsIndividualFlags) {
    nip::TcpHeader header;
    header.flags = static_cast<std::uint8_t>(nip::tcp_flag::kSyn | nip::tcp_flag::kAck);
    header.ns = true;

    EXPECT_TRUE(header.hasFlag(nip::tcp_flag::kSyn));
    EXPECT_TRUE(header.hasFlag(nip::tcp_flag::kAck));
    EXPECT_FALSE(header.hasFlag(nip::tcp_flag::kFin));
    EXPECT_TRUE(header.ns);
}

TEST(ParsedPacket, TransportPresenceFollowsParsedHeaders) {
    nip::ParsedPacket packet;
    EXPECT_FALSE(packet.hasTransportHeader());
    EXPECT_STREQ(nip::toString(packet.protocol), "Unknown");

    packet.protocol = nip::Protocol::Tcp;
    packet.tcp = nip::TcpHeader{};
    EXPECT_TRUE(packet.hasTransportHeader());
    EXPECT_STREQ(nip::toString(packet.protocol), "TCP");

    packet.tcp.reset();
    packet.protocol = nip::Protocol::IPv6;
    EXPECT_FALSE(packet.hasTransportHeader());
    EXPECT_STREQ(nip::toString(packet.protocol), "IPv6");
}

TEST(ProtocolName, MatchesCliVocabulary) {
    EXPECT_STREQ(nip::toString(nip::Protocol::Udp), "UDP");
    EXPECT_STREQ(nip::toString(nip::Protocol::Icmp), "ICMP");
    EXPECT_STREQ(nip::toString(nip::Protocol::IPv4), "IPv4");
}
