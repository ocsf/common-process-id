# SPDX-License-Identifier: Apache-2.0

find_library(CUNIT cunit)
if(NOT CUNIT)
  message(FATAL_ERROR "CUnit not found")
endif()
find_path(CUNIT_INCLUDE_DIR CUnit/CUnit.h)

set(TEST_SOURCES test_cpid_macos.c)

add_executable(${PROJECT_NAME}_test ${TEST_SOURCES})
target_include_directories(${PROJECT_NAME}_test PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${CUNIT_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME}_test ${PROJECT_NAME} ${CUNIT})
target_compile_options(${PROJECT_NAME}_test PRIVATE ${COMPILE_OPTIONS})

add_test(NAME ${PROJECT_NAME}_test COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}_test)
