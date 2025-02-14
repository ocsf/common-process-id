# SPDX-License-Identifier: Apache-2.0

if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    add_subdirectory(macos)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    add_subdirectory(linux)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    add_subdirectory(windows)
endif()
