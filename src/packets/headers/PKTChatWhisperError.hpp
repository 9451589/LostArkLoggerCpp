#pragma once

#include <cstdint>
#include <span>
#include <string>

struct PKTChatWhisperError
{
    static PKTChatWhisperError Read(std::span<uint8_t> data);

    std::wstring message;
    std::wstring recipient;
};
