#pragma once

#include <cstdint>

#include "../../data/types/Vector3.hpp"
#include "DropBoxData.hpp"

struct PKTNewDropBox
{
    static PKTNewDropBox Read(std::span<uint8_t> data);

    Vector3 dropPosition;
    uint64_t dropperEntityId;
    uint64_t dropBoxEntityId;
    std::vector<DropBoxData> dropDatas;
};
