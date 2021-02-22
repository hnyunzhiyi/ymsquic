# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    CryptTest.cpp
    DataPathTest.cpp
    # StorageTest.cpp
    TlsTest.cpp
)

# Allow CLOG to preprocess all the source files.
#add_clog_library(msquicplatformtest.clog STATIC ${SOURCES})

add_executable(ymsquicplatformtest ${SOURCES})

target_include_directories(ymsquicplatformtest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET ymsquicplatformtest PROPERTY FOLDER "tests")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_link_libraries(ymsquicplatformtest ymsquic platform inc gtest)
else()
    target_link_libraries(ymsquicplatformtest ymsquic platform inc gtest)
    #target_link_libraries(msquicplatformtest msquic platform inc gtest msquicplatformtest.clog)
endif()

add_test(NAME ymsquicplatformtest
         COMMAND ymsquicplatformtest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
