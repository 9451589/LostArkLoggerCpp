add_executable(cppLogger
    main.cpp
    sniffer.cpp
    parser.cpp
    loa_reassembly.cpp
    decompressor.cpp
    data/PKT.cpp
    data/encryption_manager.cpp
    handlers/handle_KeyExchangeClient.cpp
    handlers/handle_KeyExchangeServer.cpp
    F:/lib/imgui-1.90.8/imgui.cpp
    F:/lib/imgui-1.90.8/imgui_demo.cpp
    F:/lib/imgui-1.90.8/imgui_draw.cpp
    F:/lib/imgui-1.90.8/imgui_tables.cpp
    F:/lib/imgui-1.90.8/imgui_widgets.cpp
    F:/lib/imgui-1.90.8/backends/imgui_impl_opengl3.cpp
    F:/lib/imgui-1.90.8/backends/imgui_impl_glfw.cpp
)

include_directories(cppLogger PRIVATE
    F:/lib/nlohmann_json-3.11.3
    F:/lib/oodle
    F:/lib/pcpp-24.09/include/pcapplusplus
    F:/lib/snappy
    F:/lib/imgui-1.90.8
    F:/lib/imgui-1.90.8/backends
    F:/lib/glfw-3.4/include
    F:/lib/WinDivert-2.2.2-A/include
    F:/lib/libsodium-1.0.20-msvc/libsodium/include
)

target_compile_definitions(cppLogger PRIVATE _CONSOLE _UNICODE UNICODE SODIUM_STATIC)

target_compile_options(cppLogger PRIVATE
    /W4
    /permissive-
    /external:anglebrackets
    /external:W0
)

target_link_options(cppLogger PRIVATE /MACHINE:X64 /SUBSYSTEM:CONSOLE)

target_link_libraries(cppLogger PRIVATE
    F:/lib/oodle/lib/oo2net_win64.lib
    F:/lib/WinDivert-2.2.2-A/x64/WinDivert.lib
    F:/lib/pcpp-24.09/lib/Common++.lib
    F:/lib/pcpp-24.09/lib/Packet++.lib
    F:/lib/pcpp-24.09/lib/Pcap++.lib
    F:/lib/snappy/build/Release/snappy.lib
    F:/lib/glfw-3.4/lib/release/glfw3.lib
    F:/lib/libsodium-1.0.20-msvc/libsodium/x64/Release/v142/static/libsodium.lib
    ws2_32
    iphlpapi
    openGL32
    winmm
)
