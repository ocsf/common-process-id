# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.21)

project(cpid
    VERSION 1.0.0
    LANGUAGES C
    DESCRIPTION "Reference implementation of the CPID specification"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

if(MSVC)
  set(COMPILE_OPTIONS /W4)
else()
  set(COMPILE_OPTIONS -Wall -Wextra -Wpedantic)
endif()

add_subdirectory(src)

if(BUILD_TESTING)
  enable_testing()
  add_subdirectory(test)
endif()
