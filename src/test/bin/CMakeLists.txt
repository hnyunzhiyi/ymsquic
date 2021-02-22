# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    quic_gtest.cpp
    quic_gtest.h
)

# Allow CLOG to preprocess all the source files.
#add_clog_library(msquictest.clog STATIC ${SOURCES})

add_executable(ymsquictest ${SOURCES})

target_include_directories(ymsquictest PRIVATE ${PROJECT_SOURCE_DIR}/src/test)

set_property(TARGET ymsquictest PROPERTY FOLDER "tests")

target_link_libraries(ymsquictest ymsquic testlib platform inc gtest)

add_test(NAME ymsquictest
         COMMAND ymsquictest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
