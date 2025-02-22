#pragma once

#include <cstdint>
#include <span>

struct PKTBlockSkillStateNotify
{
    static PKTBlockSkillStateNotify Read(std::span<uint8_t> data);

    uint32_t max_stagger;
    uint32_t cur_stagger;
    uint64_t id;
};
