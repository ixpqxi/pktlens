cmake_minimum_required(VERSION 3.20)

project(pacp
    VERSION 2.0
    LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB2 REQUIRED IMPORTED_TARGET glib-2.0)
pkg_check_modules(PCAP QUIET IMPORTED_TARGET libpcap)

add_library(pacp_core STATIC
    src/capture.c
    src/capture.h
    src/packet.c
    src/packet.h
)
target_include_directories(pacp_core PUBLIC src)
target_link_libraries(pacp_core PUBLIC PkgConfig::GLIB2)

if(PCAP_FOUND)
    target_link_libraries(pacp_core PUBLIC PkgConfig::PCAP)
else()
    if(WIN32)
        set(NPCAP_SDK_DIR "" CACHE PATH
            "Root of the Npcap SDK (containing Include and Lib)")
        find_path(NPCAP_INCLUDE_DIR
            NAMES pcap.h
            HINTS "${NPCAP_SDK_DIR}/Include"
        )
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(NPCAP_LIBRARY_SUBDIR x64)
        else()
            set(NPCAP_LIBRARY_SUBDIR x86)
        endif()
        find_library(NPCAP_WPCAP_LIBRARY
            NAMES wpcap
            HINTS "${NPCAP_SDK_DIR}/Lib/${NPCAP_LIBRARY_SUBDIR}"
        )
        find_library(NPCAP_PACKET_LIBRARY
            NAMES Packet
            HINTS "${NPCAP_SDK_DIR}/Lib/${NPCAP_LIBRARY_SUBDIR}"
        )
        if(NOT NPCAP_INCLUDE_DIR OR NOT NPCAP_WPCAP_LIBRARY OR
           NOT NPCAP_PACKET_LIBRARY)
            message(FATAL_ERROR
                "Npcap SDK was not found. Set NPCAP_SDK_DIR to its root.")
        endif()
        target_include_directories(pacp_core PUBLIC "${NPCAP_INCLUDE_DIR}")
        target_link_libraries(pacp_core PUBLIC
            "${NPCAP_WPCAP_LIBRARY}"
            "${NPCAP_PACKET_LIBRARY}"
            ws2_32
        )
    else()
        find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
        find_library(PCAP_LIBRARY NAMES pcap)
        if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
            message(FATAL_ERROR
                "libpcap was not found. Install libpcap development files.")
        endif()
        target_include_directories(pacp_core PUBLIC "${PCAP_INCLUDE_DIR}")
        target_link_libraries(pacp_core PUBLIC "${PCAP_LIBRARY}")
    endif()
endif()

if(UNIX)
    target_compile_definitions(pacp_core PRIVATE _DEFAULT_SOURCE)
endif()

if(MSVC)
    target_compile_options(pacp_core PRIVATE /W4)
else()
    target_compile_options(pacp_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(pacp WIN32
    src/main.cpp
    src/main_window.cpp
    src/main_window.h
    src/capture_controller.cpp
    src/capture_controller.h
    src/packet_table_model.cpp
    src/packet_table_model.h
)
target_link_libraries(pacp PRIVATE pacp_core Qt6::Widgets)
target_include_directories(pacp PRIVATE src)

if(MSVC)
    target_compile_options(pacp PRIVATE /W4)
else()
    target_compile_options(pacp PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_executable(test_packet
    tests/test_packet.c
    src/packet.c
    src/packet.h
)
target_include_directories(test_packet PRIVATE src)
target_link_libraries(test_packet PRIVATE PkgConfig::GLIB2)
if(UNIX)
    target_compile_definitions(test_packet PRIVATE _DEFAULT_SOURCE)
endif()
if(MSVC)
    target_compile_options(test_packet PRIVATE /W4)
else()
    target_compile_options(test_packet PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(NAME packet_parser COMMAND test_packet)

install(TARGETS pacp RUNTIME DESTINATION bin)
