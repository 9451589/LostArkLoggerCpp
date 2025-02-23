#include "parser.hpp"

#include <chrono>
#include <print>

#include "data/PKT.hpp"
#include "packets.hpp"
#include "steam_opcodes.hpp"

namespace app
{

void Parser::HandleGamePacket(PKT pkt)
{
    pkt.print2();

    switch ((opcodes)pkt.opcode())
    {
        case opcodes::PKTSkillDamageNotify:
            {

            }
        case opcodes::PKTSkillDamageAbnormalMoveNotify:
            {

            }
    default:
        return;
    }
}

void Parser::reset()
{
}

} // namespace app
