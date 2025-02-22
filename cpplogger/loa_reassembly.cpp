#include "loa_reassembly.hpp"

#include <cstdint>

#include <RawPacket.h>
#include <TcpReassembly.h>

#include "parser.hpp"
#include "sniffer.hpp"

namespace app
{

/*void onApplicationInterrupted(void* cookie)*/
/*{*/
/*    auto* sniffer = static_cast<app::Sniffer*>(cookie);*/
/**/
/*    sniffer->shouldStop = true;*/
/*}*/

void tcpReassemblyMsgReadyCallback(const int8_t side, const pcpp::TcpStreamData& tcpData, void* userCookie)
{
    // get parameters from the user cookie
    auto* params = static_cast<Params*>(userCookie);

    // we only care about server to client packets
    // side can change on every run, depends on which side recieved packet first
    if ((side == 0 && (tcpData.getConnectionData().srcPort == 6040 || tcpData.getConnectionData().srcPort == 6020)) ||
        (side == 1 && (tcpData.getConnectionData().dstPort == 6040 || tcpData.getConnectionData().dstPort == 6020)))
    {

        // check if this flow already appears in the connection manager. If not add it
        // https://youtu.be/f1_Iwh33f9I?t=2979
        auto [flow, success] = params->connMgr->try_emplace(tcpData.getConnectionData().flowKey, LoaReassemblyData());

        flow->second.AppendBuffer(tcpData.getData(), tcpData.getDataLength());

        // if there are packets ready for processing, loop over buffer until there are no more ready
        while (flow->second.NextPacketReady())
        {
            params->parser->HandleGamePacket(flow->second.PopFront());
        }
    }
}

void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void* userCookie)
{
    // get parameters from the user cookie
    auto* params = static_cast<Params*>(userCookie);

    // try adding new connection to manager
    // does nothing if connection already exists
    params->connMgr->try_emplace(connectionData.flowKey, LoaReassemblyData());
}

void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData,
                                        pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
    (void)reason;

    // get parameters from the user cookie
    auto* params = static_cast<Params*>(userCookie);

    // find the connection in the connection manager by the flow key
    auto connection = params->connMgr->find(connectionData.flowKey);
    if (connection != params->connMgr->end())
    {
        // remove the connection from the connection manager
        params->connMgr->erase(connection);
    }
}

} // namespace app
