add_executable(test_math   test_math_utils.cpp)
add_executable(test_string test_string_utils.cpp)

foreach(tgt IN ITEMS test_math test_string)
    target_link_libraries(${tgt} PRIVATE demo_lib GTest::gtest)
    target_include_directories(${tgt} PRIVATE ${PROJECT_SOURCE_DIR}/include)
    add_test(NAME ${tgt} COMMAND ${tgt})
endforeach()
