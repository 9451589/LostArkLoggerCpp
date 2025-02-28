cmake_minimum_required(VERSION 3.20) #c++23
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(cppLogger LANGUAGES C CXX)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(pcapplusplus CONFIG REQUIRED)
find_package(snappy CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/sniffer.cpp
    src/parser.cpp
    src/loa_reassembly.cpp
    src/decompressor.cpp
    src/data/PKT.cpp
    src/handlers/handle_KeyExchangeClient.cpp
    src/handlers/handle_KeyExchangeServer.cpp
)

include_directories(${PROJECT_NAME} PRIVATE
    F:/lib/oodle
    F:/lib/WinDivert-2.2.2-A/include
)

target_compile_definitions(${PROJECT_NAME} PRIVATE _CONSOLE _UNICODE UNICODE SODIUM_STATIC)

target_compile_options(${PROJECT_NAME} PRIVATE
    /EHsc
    /W4
    /permissive-
    /external:anglebrackets
    /external:W0
)

target_link_options(${PROJECT_NAME} PRIVATE /MACHINE:X64 /SUBSYSTEM:CONSOLE)

target_link_libraries(${PROJECT_NAME} PRIVATE
    F:/lib/oodle/lib/oo2net_win64.lib
    F:/lib/WinDivert-2.2.2-A/x64/WinDivert.lib
    unofficial-sodium::sodium
    nlohmann_json::nlohmann_json
    PCAP::PCAP
    Packet::Packet
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Common++
    Snappy::snappy
    ws2_32
    iphlpapi
    openGL32
    winmm
)
