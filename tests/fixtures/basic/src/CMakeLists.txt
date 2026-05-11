add_library(demo_lib STATIC
    math_utils.cpp
    string_utils.cpp
)
target_include_directories(demo_lib PUBLIC ${PROJECT_SOURCE_DIR}/include)

add_executable(demo_app main.cpp)
target_link_libraries(demo_app PRIVATE demo_lib)
