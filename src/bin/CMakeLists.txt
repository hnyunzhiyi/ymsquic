# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

if(WIN32)
    set(SOURCES winuser/dllmain.c winuser/msquic.rc ${QUIC_BUILD_DIR}/inc/MsQuicEtw.rc)
else()
    set(SOURCES linux/init.c)
endif()

add_library(ymsquic SHARED ${SOURCES})

set_property(TARGET ymsquic PROPERTY FOLDER "libraries")

target_link_libraries(ymsquic PRIVATE core platform inc warnings)

if(WIN32)
    if(QUIC_UWP_BUILD)
        target_link_libraries(ymsquic PUBLIC OneCoreUAP)
    endif()
    SET_TARGET_PROPERTIES(ymsquic
        PROPERTIES LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/winuser/msquic.def\"")
else()
    SET_TARGET_PROPERTIES(ymsquic
        PROPERTIES LINK_FLAGS "-Wl,--version-script=\"${CMAKE_CURRENT_SOURCE_DIR}/linux/exports.txt\"")
endif()

target_include_directories(ymsquic PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../inc>
    $<INSTALL_INTERFACE:${include_dest}>)

set(PUBLIC_HEADERS
    ../inc/msquic.h
    ../inc/msquic_winuser.h
    ../inc/msquic_linux.h
    ../inc/quic_sal_stub.h)

install(TARGETS ymsquic EXPORT ymsquic DESTINATION "${main_lib_dest}")
install(FILES ${PUBLIC_HEADERS} DESTINATION "${include_dest}")

configure_file(msquic-config.cmake.in ${CMAKE_BINARY_DIR}/msquic-config.cmake)

install(FILES ${CMAKE_BINARY_DIR}/ymsquic-config.cmake DESTINATION ${ymsquic_dest})

install(EXPORT ymsquic DESTINATION ${ymsquic_dest})

if(WIN32)
    add_library(ymsquic.lttng INTERFACE)
elseif(QUIC_ENABLE_LOGGING)
    add_library(ymsquic.lttng SHARED $<TARGET_OBJECTS:platform.clog.provider> $<TARGET_OBJECTS:core.clog.provider>)
    target_link_libraries(ymsquic.lttng inc)
    install(TARGETS ymsquic.lttng DESTINATION "${main_lib_dest}")
endif()
