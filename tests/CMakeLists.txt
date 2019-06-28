# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(mqtthelper_test main.cpp )
target_include_directories(mqtthelper_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../include ${CMAKE_CURRENT_BINARY_DIR}/../include)
target_link_libraries(mqtthelper_test  ${GTEST_LIBRARIES} pthread dbgprint select_cb)

add_test (NAME mqtthelper COMMAND mqtthelper_test)