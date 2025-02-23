#include "sniffer.hpp"

#include <cstdint>
#include <cstdlib>
#include <print>
#include <span>
#include <string>

#include <IPv4Layer.h>
#include <PcapLiveDeviceList.h>
#include <TcpLayer.h>
#include <TcpReassembly.h>
#include <windivert.h>

#include "handlers/headers/handle_KeyExchangeClient.hpp"
#include "handlers/headers/handle_KeyExchangeServer.hpp"
#include "steam_opcodes.hpp"

namespace app
{

timeval TimestampToTimeval(int64_t ts)
{
    timeval tv{};
    LARGE_INTEGER freq{};
    QueryPerformanceFrequency(&freq);
    int64_t duration_in_microseconds = (ts / (double)freq.QuadPart) * 1e6;
    tv.tv_sec = duration_in_microseconds / 1'000'000;
    tv.tv_usec = duration_in_microseconds % 1'000'000;
    return tv;
}

// WINDIVERT SNIFFER
Sniffer::Sniffer(pcpp::TcpReassembly* tcpr) : tcpReassembly_(tcpr)
{
    const std::string filter("tcp.SrcPort == 6040 or tcp.DstPort == 6040");

    handle_ = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK_FORWARD, 0, WINDIVERT_FLAG_SNIFF);
    if (handle_ == INVALID_HANDLE_VALUE)
    {
        std::println("INVALID_HANDLE: {}", GetLastError());
        std::exit(1);
    }
}

void Sniffer::StartSniffer()
{
    WINDIVERT_ADDRESS address;
    uint8_t packet[4096];
    uint32_t recv_len{};

    std::println("sniffer running ({})", std::this_thread::get_id());
    while (true)
    {
        if (!WinDivertRecv(handle_, packet, sizeof(packet), &recv_len, &address))
        {
            std::println("WinDivertRecv failed with {}", GetLastError());
        }

        pcpp::RawPacket rawPacket(packet, recv_len, TimestampToTimeval(address.Timestamp), false, pcpp::LINKTYPE_RAW);
        tcpReassembly_->reassemblePacket(&rawPacket);
    }

    WinDivertClose(handle_);
}

void Sniffer::StopSniffer()
{
    shouldStop = true;
}

KeySniffer::KeySniffer()
{
    using enum opcodes;
    const std::string filter =
        std::format("ip.TTL > 100 and (tcp.DstPort == 6040 and tcp.Payload16[2] == {}) or (tcp.SrcPort == 6040 and "
                    "tcp.Payload16[2] == {})",
                    std::byteswap((uint16_t)PKTKeyExchangeClient), std::byteswap((uint16_t)PKTKeyExchangeServer));

    handle_ = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK_FORWARD, 1, 0);
    if (handle_ == INVALID_HANDLE_VALUE)
    {
        std::println("KEY SNIFFER: INVALID_HANDLE: {}", GetLastError());
        std::exit(1);
    }
}

void KeySniffer::StartSniffer()
{
    WINDIVERT_ADDRESS address;
    uint8_t packet[4096];
    uint32_t recv_len{};

    std::println("key sniffer running ({})", std::this_thread::get_id());
    while (true)
    {

        if (!WinDivertRecv(handle_, packet, sizeof(packet), &recv_len, &address))
        {
            std::println("WinDivertRecv failed with {}", GetLastError());
        }

        // manually set TTL to 99 to avoid impostor packets
        pcpp::RawPacket rawPacket(packet, recv_len, TimestampToTimeval(address.Timestamp), false, pcpp::LINKTYPE_RAW);
        pcpp::Packet parsedPacket(&rawPacket);
        parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getIPv4Header()->timeToLive = 99;

        uint16_t opcode{};
        auto tcp_payload = parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getLayerPayload();
        auto tcp_payload_len = parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getLayerPayloadSize();
        std::memcpy(&opcode, &tcp_payload[4], sizeof(opcode));

        using enum opcodes;
        if (opcode == (uint16_t)PKTKeyExchangeClient)
        {
            handle_KeyExchangeClient({ tcp_payload, tcp_payload_len });
        }
        else if (opcode == (uint16_t)PKTKeyExchangeServer)
        {
            handle_KeyExchangeServer({ tcp_payload, tcp_payload_len });
        }

        WinDivertHelperCalcChecksums(packet, sizeof(packet), &address, 0);

        if (!WinDivertSend(handle_, packet, sizeof(packet), &recv_len, &address))
        {
            std::println("WinDivertSend failed with {}", GetLastError());
        }
    }

    WinDivertClose(handle_);
}

} // namespace app
