#include "headers/handle_KeyExchangeServer.hpp"
#include "../data/encryption_manager.hpp"
#include "../decompressor.hpp"
#include "../reader.hpp"
#include "../steam_opcodes.hpp"

#include <print>
#include <span>

#include <ranges>
#include <snappy.h>
#include <sodium.h>

const app::Decompressor decompressor;
extern app::EncryptionData encdata;

namespace app
{

// TODO: dump this packet's parser from exe
void handle_KeyExchangeServer(std::span<uint8_t> tcp_payload)
{
    // this packet contains multiple smaller packets, get length from loa header
    uint16_t packet_len{};
    std::memcpy(&packet_len, tcp_payload.data(), sizeof(packet_len));

    // make a copy of tcp_payload, if contains pubkey we do our stuff
    // and overwrite the original with copy otherwise we send original
    std::vector<uint8_t> data(tcp_payload.begin() + 8, tcp_payload.begin() + packet_len);

    // 1. decrypt (xor)
    using enum opcodes;
    decompressor.Cipher(data, (uint32_t)PKTKeyExchangeServer);

    // 2. snappy decompress packet
    std::string decompressed;
    snappy::Uncompress(reinterpret_cast<char*>(data.data()), data.size(), &decompressed);

    // 3. save server pubkey, nonce, and msg
    auto message = encdata.message.data();
    auto nonce = encdata.nonce.data();

    std::span<uint8_t> decomp_span(reinterpret_cast<uint8_t*>(decompressed.data()), decompressed.size());
    app::BitReader reader(decomp_span);

    reader.skip(16);
    reader.memcpy_(nonce, reader.u32());
    reader.memcpy_(message, reader.u32());
    reader.skip(2);
    reader.memcpy_(encdata.s_pubkey.data(), reader.u32());

    // 3. decrypt message
    if (crypto_box_open_easy(message, message, 56, nonce, encdata.s_pubkey.data(), encdata.my_sk.data()) == 0)
    {
        std::println("\ncrypto_box_open_easy SUCCESS");

        // save chacha20 key / nonce
        std::memcpy(encdata.chacha20_key.data(), message, crypto_stream_chacha20_KEYBYTES);
        std::memcpy(encdata.chacha20_nonce.data(), message + crypto_stream_chacha20_KEYBYTES,
                    crypto_stream_chacha20_NONCEBYTES);

        std::println("chacha key");
        std::println("{::02X} ", encdata.chacha20_key);
        std::println("chacha nonce");
        std::println("{::02X} ", encdata.chacha20_nonce);

        // re-encrypt message using game client's pub key and our secret key
        if (crypto_box_easy(message, message, 40, nonce, encdata.c_pubkey.data(), encdata.my_sk.data()) != 0)
            std::println("crypto_box_easy error");

        // modify packet copy, send my pubkey and re encrypted msg
        std::memcpy(decompressed.data() + 16 + 4 + 24 + 4, message, 56);                           // msg
        std::memcpy(decompressed.data() + 16 + 4 + 24 + 4 + 56 + 2 + 4, encdata.my_pk.data(), 32); // my pubkey

        // re compress packet
        std::string recompressed;
        snappy::Compress(reinterpret_cast<char*>(decompressed.data()), decompressed.size(), &recompressed);

        // check if re compressed size == original compressed size
        // if different we bail, send original un modified packet
        if (packet_len - 8 != recompressed.size())
        {
            std::println("compressed size mismatch: {} - {}", packet_len - 8, recompressed.size());
            return;
        }

        // re-encrypt (xor)
        std::span<uint8_t> recomp_span(reinterpret_cast<uint8_t*>(recompressed.data()), recompressed.size());
        decompressor.Cipher(recomp_span, (int32_t)opcodes::PKTKeyExchangeServer);

        // overwrite original packet
        std::memcpy(tcp_payload.data() + 8, recompressed.data(), recompressed.size());
    }
}

} // namespace app
