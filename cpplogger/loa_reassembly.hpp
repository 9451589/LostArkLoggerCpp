#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <unordered_map>

#include <TcpReassembly.h>

#include "data/PKT.hpp"
#include "decompressor.hpp"
#include "parser.hpp"

// global
extern const app::Decompressor decompressor;

namespace app
{

struct LoaHeader
{
    uint16_t len;
    uint16_t u16_0;
    uint16_t opcode;
    uint8_t compression;
    int8_t encrypted;
};

constexpr uint8_t LOAHDR = sizeof(LoaHeader);
static_assert(LOAHDR == 8, "sizeof(LoaHeader) != 8");

// TODO: keep timestamps with PKTs
struct LoaReassemblyData
{
  private:
    int bufferSize = 1024 * 200; // 200KB

    // buffer where we defragment game packets
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(bufferSize);

    // the number of bytes written to our buffer
    std::size_t len{0};

    // tail points to where we append next
    uint8_t* tail = buffer.get();

    // head points to the beginning of our current game packet (game packet header)
    uint8_t* head = buffer.get();

  public:
    void AppendBuffer(const uint8_t* data, const size_t datalen)
    {
        // check if header is valid before appending to buffer
        if (len == 0 && !isHeaderValid(data))
        {
            return;
        }

        memcpy(tail, data, datalen);
        len += datalen;
        tail += datalen;
    }

    // not popping anything, just sliding pointers
    // need a complete packet to decrypt/decompress it
    // returns a complete game packet that can be decompressed/decrypted
    PKT PopFront()
    {
        // can't guarantee head alignment, can't pun?
        LoaHeader lah;
        memcpy(&lah, head, LOAHDR);
        PKT pkt(head + LOAHDR, lah.len - LOAHDR, lah.opcode, lah.encrypted, lah.compression, &decompressor);
        head += lah.len;
        len -= lah.len;
        if (len == 0)
        {
            head = tail = buffer.get();
        }
        return pkt;
    }

    static bool isHeaderValid(const uint8_t* data)
    {
        // "data" is guaranteed to be aligned, pun
        const auto* lah = reinterpret_cast<const LoaHeader*>(data);

        return lah->len >= LOAHDR && lah->u16_0 == 0 && lah->compression < 4 && lah->encrypted < 2;
    }

    // are there enough bytes in our buffer for a complete packet?
    [[nodiscard]] bool NextPacketReady() const
    {
        // "head" might not be aligned, cant pun?
        LoaHeader lah;
        std::memcpy(&lah, head, sizeof(LoaHeader));

        return len > 0 && len >= lah.len;
    }
};

// typedef representing the connection manager
using TcpReassemblyConnMgr = std::unordered_map<uint32_t, LoaReassemblyData>;

// callbacks
void onApplicationInterrupted(void* cookie);
/*void onPacketArrives(uint8_t* params, const struct pcap_pkthdr* header, const uint8_t* pkt_data);*/
void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData& tcpData, void* userCookie);
void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void* userCookie);
void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData,
                                        pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie);
// pass arguments to our callbacks
struct Params
{
    app::Parser* parser;
    app::TcpReassemblyConnMgr* connMgr;
};

} // namespace app
