cmake_minimum_required (VERSION 3.18)
project (OG-Injector-Linux VERSION 1.0.0 LANGUAGES CXX)

add_executable(${PROJECT_NAME} "OG-Injector-Linux.cpp" "OG-Injector-Linux.hpp" "OG-Injector-Lib/elf.cpp" "OG-Injector-Lib/ptrace.cpp" "OG-Injector-Lib/remote_call.cpp" "OG-Injector-Lib/util.cpp" "OG-Injector-Lib/OG-Injector-Lib.cpp" "OG-Injector-Lib/OG-Injector-Lib.hpp" "OG-Injector-Lib/OG-Injector-Lib-internal.hpp")

target_compile_options(${PROJECT_NAME} PRIVATE -Wall
												 -Wno-unknown-pragmas
												 -Wno-comment)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
target_link_libraries(${PROJECT_NAME} -static)