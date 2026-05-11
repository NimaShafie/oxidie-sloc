cmake_minimum_required(VERSION 3.11)
project(nlohmann_json LANGUAGES CXX)

add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(nlohmann_json INTERFACE cxx_std_17)

add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
