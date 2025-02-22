#pragma once

#include <cstdint>
#include <span>

#include "../../data/types/SkillMoveOptionData.hpp"
#include "../../data/types/Vector3.hpp"

struct PKTMoveNotify
{
    static PKTMoveNotify Read(std::span<uint8_t> data);

    uint8_t u8_0;
    uint16_t angle;
    Vector3 vec3_0;
    Vector3 vec3_1;
    uint64_t entityId;
    uint64_t packed_0;
    SkillMoveOptionData moveData;
};
