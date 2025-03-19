# SPDX-License-Identifier: Apache-2.0

set(LIBRARY_SOURCES cpid_windows.c)
set(CLI_SOURCES main.c)

add_library(${PROJECT_NAME} ${LIBRARY_SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME} INTERFACE ntdll rpcrt4 bcrypt)

add_executable(${PROJECT_NAME}_cli ${CLI_SOURCES})
target_include_directories(${PROJECT_NAME}_cli PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME}_cli ${PROJECT_NAME})
