#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace app
{

class Decompressor
{
  public:
    Decompressor();
    Decompressor(Decompressor&) = delete;

    void Cipher(std::span<uint8_t> data, int32_t seed) const;
    std::vector<uint8_t> Decompress(std::span<uint8_t> compressed, uint8_t compressionType, uint16_t opcode,
                                    bool encrypted) const;

  private:
    std::unique_ptr<char[]> oodleState;
    std::unique_ptr<char[]> oodleShared;
    std::unique_ptr<char[]> initDict;
    std::array<uint8_t, 256> xorTable{0};
};

} // namespace app
