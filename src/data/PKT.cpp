#include "PKT.hpp"

#include <print>
#include <ranges>

namespace app
{

PKT::PKT(uint8_t* data, uint16_t len, uint16_t opcode, uint8_t enc, uint8_t compression, const Decompressor* d)
    : encrypted_(enc), opcode_(opcode), compression_(compression), data_{data, data + len}, decompressor_(d)
{
}

void PKT::print()
{
    bool first_chunk = true;
    for (auto chunk : decompressed() | std::views::chunk(32))
    {
        if (first_chunk)
        {
            first_chunk = false;
            std::println("{:04X}:   {:n:02X}", opcode(), chunk);
        }
        else
        {
            std::println("\t{:n:02X}", chunk);
        }
    }
    std::println();
}

void PKT::print2()
{
    auto chunks = decompressed() | std::views::chunk(32);

    for (const auto chunk : chunks | std::views::take(1))
        std::println("{:04X}:   {:n:02X}", opcode(), chunk);

    for (const auto chunk : chunks | std::views::drop(1))
            std::println("\t{:n:02X}", chunk);
}

std::vector<uint8_t>& PKT::decompressed()
{
    if (decompressed_.empty())
    {
        decompressed_ = decompressor_->Decompress(data_, compression_, opcode_, encrypted_);
    }

    return decompressed_;
}

} // namespace app
