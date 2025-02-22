#pragma once

#include <array>
#include <cstdint>

#include <sodium.h>

namespace app
{

struct EncryptionData
{
    // our private/public keys
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> my_pk{
        0x4B, 0x1B, 0x1B, 0x83, 0x04, 0x98, 0x75, 0xA0, 0xE9, 0xF4, 0x86, 0xA7, 0x9E, 0x09, 0x9D, 0xD9,
        0x6C, 0xA9, 0xBB, 0xFD, 0xE8, 0x2E, 0x85, 0x75, 0x7C, 0x7F, 0x09, 0x29, 0x15, 0xEE, 0x45, 0x56};

    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> my_sk{
        0x3A, 0x65, 0xAC, 0xD9, 0xE0, 0x7F, 0x5F, 0xE2, 0x3B, 0x56, 0x4F, 0x3A, 0xCE, 0x54, 0x4C, 0x95,
        0x57, 0xDA, 0x07, 0x0E, 0xC6, 0xE8, 0xE6, 0xB6, 0x7F, 0xF1, 0xC1, 0x5F, 0xC6, 0xD9, 0x1E, 0x79};

    // sent from server
    // used, along with our pubkey, to decrypt server msg
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> s_pubkey{};
    std::array<uint8_t, crypto_box_NONCEBYTES> nonce{};

    // server msg encrypted with crypto_box_easy
    // contains chacha20 key, chacha20 nonce used for dmg packets
    std::array<uint8_t, 0x38> message{};

    // game clients pubkey, used to re-encrypt above msg for use by the game client
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> c_pubkey{};

    // chacha20 key / nonce. used to decrypt dmg packets
    std::array<uint8_t, crypto_stream_chacha20_KEYBYTES> chacha20_key{};
    std::array<uint8_t, crypto_stream_chacha20_NONCEBYTES> chacha20_nonce{};
};

} // namespace app
