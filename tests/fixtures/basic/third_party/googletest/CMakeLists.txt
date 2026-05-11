cmake_minimum_required(VERSION 3.11)
project(googletest LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)

add_library(gtest STATIC
    googletest/src/gtest-all.cc
)
target_include_directories(gtest PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/googletest/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/googletest>
    $<INSTALL_INTERFACE:include>
)
target_compile_definitions(gtest PUBLIC GTEST_HAS_PTHREAD=0)

add_library(GTest::gtest ALIAS gtest)
