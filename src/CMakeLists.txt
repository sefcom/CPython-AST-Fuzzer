cmake_minimum_required(VERSION 3.18)
project(pyFuzzer VERSION 0.1 LANGUAGES C)
set(CMAKE_C_STANDARD 17)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
add_library(pyFuzzer_common INTERFACE)

message(STATUS "PYTHON_PATH: $ENV{PYTHON_PATH}")

SET(CPYTHON_VER "3.13")
SET(PYTHON_VER 313)

target_include_directories(pyFuzzer_common INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerHelper
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerHelper/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerTarget
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/codgen
    $ENV{PYTHON_PATH}/include/python${CPYTHON_VER}
    $ENV{PYTHON_PATH}/include/python${CPYTHON_VER}/internal # idk why Python3_INCLUDE_DIR is empty and Python3_INCLUDE_DIRS only contain one path
)
# with debug symbol
target_compile_definitions(pyFuzzer_common INTERFACE PYTHON_VER=${PYTHON_VER})
target_compile_options(pyFuzzer_common INTERFACE -fsanitize=address,fuzzer -O3 -march=native)
target_link_options(pyFuzzer_common INTERFACE -fsanitize=address,fuzzer)

message(STATUS "PYTHON_PATH: $ENV{PYTHON_PATH}")
target_link_libraries(pyFuzzer_common INTERFACE $ENV{PYTHON_PATH}/lib/libpython${CPYTHON_VER}.so)

# -- pyFuzzerHelper -- 
# mutators, utils and ast helpers etc

file(GLOB SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerHelper/utils/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerHelper/mutators/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerHelper/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerTarget/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/common/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/common/hash.h
    ${CMAKE_CURRENT_SOURCE_DIR}/codgen/*.c
)

add_executable(pyFuzzerHelper ${SRC_FILES})
target_link_libraries(pyFuzzerHelper PRIVATE pyFuzzer_common)
set_target_properties(pyFuzzerHelper PROPERTIES PREFIX "" SUFFIX "")