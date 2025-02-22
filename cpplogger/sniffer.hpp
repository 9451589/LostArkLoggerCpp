#pragma once

#include <TcpReassembly.h>
#include "decompressor.hpp"

extern const app::Decompressor decompressor;

namespace app
{

class Sniffer
{
  public:
    Sniffer() = default;
    Sniffer(pcpp::TcpReassembly*);

    virtual void StartSniffer();
    void StopSniffer();
    HANDLE handle() const { return handle_; }
    pcpp::TcpReassembly* tcpReassembly() const { return tcpReassembly_; }

    bool shouldStop = false;

  protected:
    pcpp::TcpReassembly* tcpReassembly_;
    HANDLE handle_ = nullptr;
};

class KeySniffer : public Sniffer
{
  public:
    KeySniffer();
    void StartSniffer() override;
};

}; // namespace app
