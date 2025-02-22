#include "headers/handle_KeyExchangeClient.hpp"
#include "../data/encryption_data.hpp"
#include "../decompressor.hpp"

#include <print>

extern const app::Decompressor decompressor;
extern app::EncryptionData encdata;

namespace app
{

// TODO: dump this packet's parser from exe
void handle_KeyExchangeClient(std::span<uint8_t> tcp_payload)
{
    // make a copy of tcp_payload. if it contains the game client's pubkey,
    //  we do our stuff and overwrite the original with copy
    std::vector<uint8_t> data(tcp_payload.begin() + 8, tcp_payload.end());

    // 1. Decrypt (xor) packet
    // seed for xor is 1, always the second packet sent
    decompressor.Cipher(data, 1);

    // 2. if packet constains key
    uint32_t key_len{};
    std::memcpy(&key_len, data.data() + 16, sizeof(key_len)); // skip 16 bytes counter + random
    if (key_len == 32)
    {
        // save clients pubkey
        std::memcpy(encdata.c_pubkey.data(), data.data() + 16 + 4, key_len);

        // overwrite with our pubkey
        std::memcpy(data.data() + 16 + 4, encdata.my_pk.data(), key_len);

        // re-encrypt (xor)
        decompressor.Cipher(data, 1);

        // overwrite original packet
        std::memcpy(tcp_payload.data() + 8, data.data(), data.size());
    }
}

} // namespace app
