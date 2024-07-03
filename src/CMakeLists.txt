cmake_minimum_required(VERSION 3.18)
project(pyFuzzer VERSION 0.1 LANGUAGES C)
set(CMAKE_C_STANDARD 17)

find_package(Python3 COMPONENTS Development)

file(GLOB SRC_FILES
${CMAKE_CURRENT_SOURCE_DIR}/*.c
${CMAKE_CURRENT_SOURCE_DIR}/utils/*.c)
message(STATUS "SRC_FILES: ${SRC_FILES}")

add_library(pyFuzzer SHARED ${SRC_FILES})

target_include_directories(pyFuzzer PRIVATE
    ${Python3_INCLUDE_DIRS}
    ${Python3_INCLUDE_DIRS}/internal # idk why Python3_INCLUDE_DIR is empty and Python3_INCLUDE_DIRS only contain one path
)
target_link_libraries(pyFuzzer PRIVATE ${Python3_LIBRARIES})
set_target_properties(pyFuzzer PROPERTIES PREFIX "" SUFFIX ".so" OUTPUT_NAME "pyFuzzer")