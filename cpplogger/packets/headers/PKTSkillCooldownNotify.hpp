#pragma once

#include <cstdint>
#include <span>

struct PKTSkillCooldownNotify
{
    uint32_t skill_id;
    float cooldown1;
    float cooldown2;

    static PKTSkillCooldownNotify Read(std::span<uint8_t> data);
};
