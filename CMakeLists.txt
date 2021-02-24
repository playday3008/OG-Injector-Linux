cmake_minimum_required (VERSION 3.8)

project ("OG-Injector-Linux")

add_executable (OG-Injector-Linux "OG-Injector-Linux.cpp" "OG-Injector-Linux.hpp" "OG-Injector-Lib/elf.cpp" "OG-Injector-Lib/ptrace.cpp" "OG-Injector-Lib/remote_call.cpp" "OG-Injector-Lib/util.cpp" "OG-Injector-Lib/OG-Injector-Lib.cpp" "OG-Injector-Lib/OG-Injector-Lib.hpp" "OG-Injector-Lib/OG-Injector-Lib-internal.hpp")
set(CMAKE_C_COMPILER "gcc-10")
set(CMAKE_CXX_COMPILER "g++-10")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "-Wall -Wno-unknown-pragmas -Wno-comment -std=c++2a -lstdc++fs")
