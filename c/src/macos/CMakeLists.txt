# SPDX-License-Identifier: Apache-2.0

find_package(OpenSSL REQUIRED)

find_library(IOKIT_LIBRARY IOKit)
if(NOT IOKIT_LIBRARY)
  message(FATAL_ERROR "IO Kit not found")
endif()

find_library(COREFOUNDATION_LIBRARY CoreFoundation)
if(NOT COREFOUNDATION_LIBRARY)
  message(FATAL_ERROR "Core Foundation not found")
endif()

# libuuid is part of the system libraries on macOS
# so we don't need to find it explicitly

set(LINK_LIBRARIES OpenSSL::Crypto ${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY})
set(LIBRARY_SOURCES cpid_macos.c)
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
