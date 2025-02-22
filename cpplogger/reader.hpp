#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace app
{

class BitReader
{
    std::span<uint8_t> d;
    std::size_t offset{0};

  public:
    BitReader(std::span<uint8_t> data) : d(data) {}

    void skip(int32_t num) { offset += num; }

    bool Bool() { return u8() == 1; }

    uint8_t u8()
    {
        // don't have to worry about alignment, pun
        const uint8_t r = *(d.data() + offset);
        offset += sizeof(uint8_t);
        return r;
    }

    // unfortunately can't guarantee alignment
    // use memcpy for everything else
    uint16_t u16()
    {
        uint16_t r{};
        memcpy(&r, d.data() + offset, sizeof(r));
        offset += sizeof(uint16_t);
        return r;
    }

    uint32_t u32()
    {
        uint32_t r{};
        memcpy(&r, d.data() + offset, sizeof(r));
        offset += sizeof(uint32_t);
        return r;
    }

    uint64_t u64()
    {
        uint64_t r{};
        memcpy(&r, d.data() + offset, sizeof(r));
        offset += sizeof(uint64_t);
        return r;
    }

    float f32()
    {
        float r{};
        memcpy(&r, d.data() + offset, sizeof(r));
        offset += sizeof(float);
        return r;
    }

    int64_t PackedInt()
    {
        int64_t r{};
        const uint8_t flag = u8();
        const uint8_t num = (flag >> 1) & 7;
        memcpy(&r, d.data() + offset, num);
        offset += num;
        r = r << 4 | flag >> 4;
        if (flag & 1) r = -r;
        return r;
    }

    uint64_t SimpleInt()
    {
        const uint16_t s = u16();
        if ((s & 0xfff) < 0x81f)
        {
            offset -= 2;
            return u64();
        }
        else
        {
            return (s & 0xFFF) | 0x11000;
        }
    }

    void memcpy_(uint8_t* dst, std::size_t length, std::size_t stride = 1)
    {
        std::memcpy(dst, d.data() + offset, length * stride);
        offset += length * stride;
    }

    std::vector<uint8_t> Bytes(std::size_t length, std::size_t stride = 1)
    {
        std::vector<uint8_t> v;
        v.resize(length * stride);
        memcpy(v.data(), d.data() + offset, length * stride);
        offset += length * stride;
        return v;
    }

    template <typename T>
    std::vector<T> ReadList(int num, T(*f)(app::BitReader&))
    {
        std::vector<T> ret;
        for (int i = 0; i < num; i++)
        {
            ret.push_back(std::invoke(f, *this));
        }
        return ret;
    }

    std::wstring String()
    {
        const auto len = u16();
        std::wstring s;
        s.resize(len);
        memcpy(s.data(), d.data() + offset, len * 2);
        offset += len * 2;
        return s;
    }
};

} // namespace app
