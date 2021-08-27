# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_quic_tool(tcpclient tcpclient.cpp)
quic_tool_warnings(tcpclient)

target_include_directories(tcpclient PRIVATE ${PROJECT_SOURCE_DIR}/src/tools/tcp)
