#pragma once

#include <cstdint>
#include <span>

#include "../../data/types/Vector3.hpp"

struct PKTMoveStopNotify
{
    static PKTMoveStopNotify Read(std::span<uint8_t> data);

    uint16_t angle;
    Vector3 vec3_0;
    uint64_t entityId;
};
