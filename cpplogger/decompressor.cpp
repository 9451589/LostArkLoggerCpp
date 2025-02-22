#include "decompressor.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <print>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <oodle2net.h>
#include <snappy.h>

// for now, anything in constructor throws or errors we exit
// in the future invalid decompressor state is ok. we can't
// parse packets, but maybe still look at logs and stuff
namespace app
{

Decompressor::Decompressor()
{
    std::string filename(R"(meter-data\oodle_state.bin)");
    std::ifstream file(filename, std::ifstream::binary);

    if (!file.is_open())
    {
        std::println(std::cerr, "Error opening {}", filename);
        std::exit(1);
    }

    initDict = std::make_unique_for_overwrite<char[]>(0x800'000);
    file.seekg(0x20, std::ifstream::beg);
    file.read(initDict.get(), 0x800'000);

    int32_t compressorSize{};
    file.seekg(0x18, std::ifstream::beg);
    file.read(reinterpret_cast<char*>(&compressorSize), sizeof(compressorSize));

    auto compressorState = std::make_unique_for_overwrite<char[]>(compressorSize);
    file.seekg(0x800'020, std::ifstream::beg);
    file.read(compressorState.get(), compressorSize);

    oodleState = std::make_unique_for_overwrite<char[]>(OodleNetwork1UDP_State_Size());

    if (!OodleNetwork1UDP_State_Uncompact(reinterpret_cast<OodleNetwork1UDP_State*>(oodleState.get()),
                                          reinterpret_cast<OodleNetwork1UDP_StateCompacted*>(compressorState.get())))
    {
        std::println(std::cerr, "oodle init failed");
        std::exit(1);
    }

    oodleShared = std::make_unique_for_overwrite<char[]>(OodleNetwork1_Shared_Size(0x13));
    OodleNetwork1_Shared_SetWindow(reinterpret_cast<OodleNetwork1_Shared*>(oodleShared.get()), 0x13, initDict.get(),
                                   0x800'000);

    file.close();

    filename = R"(meter-data\xor.bin)";
    file.open(filename, std::ifstream::binary);

    if (!file.is_open())
    {
        std::println(std::cerr, "Error opening {}", filename);
        std::exit(1);
    }

    file.seekg(0, std::ifstream::end);
    const std::streampos fileSize = file.tellg();

    if (fileSize != 256)
    {
        std::println(std::cerr, "bad xor");
        std::exit(1);
    }

    file.seekg(0, std::ifstream::beg);
    file.read(reinterpret_cast<char*>(xorTable.data()), 256);
    file.close();
}

void Decompressor::Cipher(std::span<uint8_t> data, int32_t seed) const
{
    for (auto& i : data)
    {
        i ^= xorTable.at(seed++ % 256);
    }
}

std::vector<uint8_t> Decompressor::Decompress(std::span<uint8_t> compressed, uint8_t compressionType, uint16_t opcode,
                                              bool encrypted) const
{
    if (encrypted)
    {
        Cipher(compressed, opcode);
    }

    std::vector<uint8_t> decompressed;
    std::size_t decompressed_size{0};

    switch (compressionType)
    {
        case 0: // None
            decompressed = {compressed.begin(), compressed.end()};
            break;

        case 1: // LZ4
            break;

        case 2: // Snappy
            if (snappy::GetUncompressedLength(reinterpret_cast<char*>(compressed.data()), compressed.size(),
                                              &decompressed_size))
            {
                decompressed.resize(decompressed_size);

                if (!snappy::RawUncompress(reinterpret_cast<char*>(compressed.data()), compressed.size(),
                                           reinterpret_cast<char*>(decompressed.data())))
                {
                    std::println(std::cerr, "snappy decompress failed");
                }
            }
            break;

        case 3: // Oodle
            memcpy(&decompressed_size, compressed.data(), sizeof(uint32_t));
            decompressed.resize(decompressed_size);

            if (!OodleNetwork1UDP_Decode(reinterpret_cast<OodleNetwork1UDP_State*>(oodleState.get()),
                                         reinterpret_cast<OodleNetwork1_Shared*>(oodleShared.get()),
                                         compressed.data() + 4, compressed.size() - 4, decompressed.data(),
                                         decompressed.size()))
            {
                std::println(std::cerr, "oodle decompress failed");
            }
            break;

        default:
            std::unreachable();
    }

    if (decompressed.size() > 16)
    {
        decompressed.erase(decompressed.begin(), decompressed.begin() + 16);
    }

    return decompressed;
}

} // namespace app
