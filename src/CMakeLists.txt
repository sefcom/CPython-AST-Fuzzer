cmake_minimum_required(VERSION 3.18)
project(pyFuzzer VERSION 0.1 LANGUAGES C)
set(CMAKE_C_STANDARD 17)

# message(STATUS "Python path: $ENV{PYTHON_PATH}")
# find_package(Python3 EXACT 3.11.9 REQUIRED COMPONENTS Development) # not works since nix's python doesn't have cmake file

add_library(pyFuzzer_common INTERFACE)

# target_include_directories(pyFuzzer_common INTERFACE ${Python3_INCLUDE_DIRS} ${Python3_INCLUDE_DIRS}/internal)
# target_link_libraries(pyFuzzer_common INTERFACE ${Python3_LIBRARIES})


target_include_directories(pyFuzzer_common INTERFACE
    $ENV{PYTHON_PATH}/include/python3.11
    $ENV{PYTHON_PATH}/include/python3.11/internal # idk why Python3_INCLUDE_DIR is empty and Python3_INCLUDE_DIRS only contain one path
)
target_compile_options(pyFuzzer_common INTERFACE -O3 -march=native -fsanitize=address,fuzzer-no-link)
target_link_options(pyFuzzer_common INTERFACE -fsanitize=address,fuzzer-no-link)

# file(GLOB PATCHED_LIBS ${CMAKE_CURRENT_SOURCE_DIR}/../patched_libs/*)
# message(STATUS "Patched libs: ${PATCHED_LIBS}")
# target_link_libraries(pyFuzzer_common INTERFACE ${PATCHED_LIBS})

# -- pyFuzzerHelper -- 
# mutators, utils and ast helpers etc

file(GLOB HELPER_SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerHelper/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerHelper/utils/*.c
)

add_library(pyFuzzerHelper SHARED ${HELPER_SRC_FILES})
target_link_libraries(pyFuzzerHelper PRIVATE pyFuzzer_common)
set_target_properties(pyFuzzerHelper PROPERTIES PREFIX "" SUFFIX ".so")

# -- pyFuzzerTarget --
file(GLOB TARGET_SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/fuzzerTarget/*.c
)

add_library(pyFuzzerTarget SHARED ${TARGET_SRC_FILES})
target_link_libraries(pyFuzzerTarget PRIVATE pyFuzzer_common)
set_target_properties(pyFuzzerTarget PROPERTIES PREFIX "" SUFFIX ".so")
