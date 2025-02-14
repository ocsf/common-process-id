# SPDX-License-Identifier: Apache-2.0

find_package(OpenSSL REQUIRED)

find_library(UUID_LIBRARY uuid)
if(NOT UUID_LIBRARY)
  message(FATAL_ERROR "libuuid not found")
endif()

set(LINK_LIBRARIES OpenSSL::Crypto ${UUID_LIBRARY})
set(LIBRARY_SOURCES cpid_linux.c)
set(CLI_SOURCES main.c)

add_library(${PROJECT_NAME} ${LIBRARY_SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME} ${LINK_LIBRARIES})
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

add_executable(${PROJECT_NAME}_cli ${CLI_SOURCES})
target_include_directories(${PROJECT_NAME}_cli PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(${PROJECT_NAME}_cli ${PROJECT_NAME})
target_compile_options(${PROJECT_NAME}_cli PRIVATE ${COMPILE_OPTIONS})
