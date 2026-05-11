cmake_minimum_required(VERSION 3.16)
project(demo_project VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Optional: instrument for gcov/lcov
option(ENABLE_COVERAGE "Enable code coverage instrumentation" OFF)
if(ENABLE_COVERAGE)
    add_compile_options(--coverage -O0 -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
endif()

# Submodule dependencies
add_subdirectory(third_party/json)
add_subdirectory(third_party/googletest)

# Main library + binary
add_subdirectory(src)

# Unit tests
enable_testing()
add_subdirectory(tests)
