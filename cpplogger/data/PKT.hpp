#pragma once

#include <cstdint>
#include <format>
#include <span>
#include <vector>

#include "../decompressor.hpp"

// Specialization for the range formatter type
// probably shouldn't do this, can we just get fmt::join?
template <class T, class charT>
struct std::formatter<std::ranges::subrange<std::_Vector_iterator<std::_Vector_val<std::_Simple_types<T>>>>, charT>
    : std::range_formatter<T, charT>
{
    constexpr formatter() { this->set_separator(" "); }
};

namespace app
{

class PKT
{
  public:
    PKT() = delete;

    PKT(uint8_t* data, uint16_t len, uint16_t opcode, uint8_t enc, uint8_t compression, const Decompressor* d);

    void print();

    std::vector<uint8_t>& decompressed();

    std::span<uint8_t> data() { return data_; }

    uint16_t opcode() const { return opcode_; }

  private:
    bool encrypted_;
    uint16_t opcode_;
    uint8_t compression_;
    std::span<uint8_t> data_;
    std::vector<uint8_t> decompressed_;
    const Decompressor* decompressor_;
};

} // namespace app
