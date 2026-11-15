cmake_minimum_required(VERSION 3.20)

project(nip
    VERSION 0.1.0
    DESCRIPTION "Network Intelligence Platform packet parser"
    LANGUAGES CXX)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

function(nip_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

add_library(nip_parse
    src/byte/ByteReader.cpp
    src/model/Addresses.cpp
    src/model/Protocol.cpp)
target_include_directories(nip_parse PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(nip_parse PUBLIC cxx_std_17)
nip_set_warnings(nip_parse)
add_library(nip::parse ALIAS nip_parse)

include(CTest)
if(BUILD_TESTING)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
        GIT_SHALLOW TRUE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    add_subdirectory(tests)
endif()
