#include <iostream>
#include <print>

#include <PcapLiveDeviceList.h>
#include <sodium.h>
#include <SystemUtils.h>
#include <TcpReassembly.h>

#include "decompressor.hpp"
#include "loa_reassembly.hpp"
#include "parser.hpp"
#include "sniffer.hpp"
#include "data/encryption_manager.hpp"

// Global for now
const app::Decompressor decompressor;
app::EncryptionData encdata;

int main(int, char**)
{
    if (sodium_init() == -1)
    {
        std::println(std::cerr, "Sodium init failed");
    }

    // pcapplusplus tcp reassembly stuff
    app::Parser parser;
    app::TcpReassemblyConnMgr connMgr;
    app::Params params(&parser, &connMgr);
    pcpp::TcpReassembly tcpReassembly(app::tcpReassemblyMsgReadyCallback, &params,
                                      app::tcpReassemblyConnectionStartCallback,
                                      app::tcpReassemblyConnectionEndCallback);

    // create our packet captures
    app::Sniffer sniffer(&tcpReassembly);
    app::KeySniffer mitm_sniffer;

    // capture loops forever, this is how we break out
    /*pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(*/
    /*    app::onApplicationInterrupted, &sniffer);*/

    // start the capture
    std::thread mitm_thread{[&mitm_sniffer] { mitm_sniffer.StartSniffer(); }};
    sniffer.StartSniffer();

    mitm_thread.join();

    // done. close connections, print some stats
    tcpReassembly.closeAllConnections();
    std::println("Done! processed {} connections\n",
                 tcpReassembly.getConnectionInformation().size());
}
