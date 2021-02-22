# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(SOURCES
    main.cpp
    FrameTest.cpp
    PacketNumberTest.cpp
    PartitionTest.cpp
    RangeTest.cpp
    SpinFrame.cpp
    TicketTest.cpp
    TransportParamTest.cpp
    VarIntTest.cpp
)

# Allow CLOG to preprocess all the source files.
#add_clog_library(msquiccoretest.clog STATIC ${SOURCES})

add_executable(ymsquiccoretest ${SOURCES})

target_include_directories(ymsquiccoretest PRIVATE ${PROJECT_SOURCE_DIR}/src/core)

set_property(TARGET ymsquiccoretest PROPERTY FOLDER "tests")

target_link_libraries(ymsquiccoretest ymsquic core platform inc gtest)

add_test(NAME ymsquiccoretest
         COMMAND ymsquiccoretest
         WORKING_DIRECTORY ${QUIC_OUTPUT_DIR})
