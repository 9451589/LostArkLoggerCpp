#pragma once

#include <chrono>
#include <print>

#include "data/PKT.hpp"

namespace app
{

using namespace std::chrono;

class Parser
{
  public:
    void HandleGamePacket(PKT pkt);
    void reset();

  private:
    // measure skill cast to add buff delay
    steady_clock::time_point start;
    steady_clock::time_point end;

    // measure identity gauge gain
    uint32_t cur_gauge{0};
    uint32_t prev_gauge{0};
};

} // namespace app
