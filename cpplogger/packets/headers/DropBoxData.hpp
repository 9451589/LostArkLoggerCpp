#pragma once

#include "../../reader.hpp"

#include <cstdint>

struct DropBoxData
{
    enum class dropentitytype : uint8_t
    {
        na,
        item,
        money,
        ether,
        bound_gold,
    };

    static DropBoxData Read(app::BitReader& reader);

    // PrimaryKey in database
    uint32_t ether_id;
    dropentitytype drop_type;
};
