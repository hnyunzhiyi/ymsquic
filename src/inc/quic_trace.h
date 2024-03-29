/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic defines two classes of tracing:

    Events      These are well-defined and have explicit formats. Each event is
                defined with its own, unique function. These are generally used
                for automated log processing (quicetw for instance).

    Logs        These use a printf style format for generally tracing more
                detailed information than Events, and are purely for human
                consumption.

    Each class is individually configurable at compile time. Different platforms
    or build configurations can have their own desired behavior. The following
    configuration options are currently supported:

    QUIC_EVENTS_STUB            No-op all Events
    QUIC_EVENTS_MANIFEST_ETW    Write to Windows ETW framework

    QUIC_LOGS_STUB              No-op all Logs
    QUIC_LOGS_MANIFEST_ETW      Write to Windows ETW framework

    QUIC_CLOG                   Bypasses these mechanisms and uses CLOG to generate logging

 --*/

#pragma once

typedef enum QUIC_FLOW_BLOCK_REASON {
    QUIC_FLOW_BLOCKED_SCHEDULING            = 0x01,
    QUIC_FLOW_BLOCKED_PACING                = 0x02,
    QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT    = 0x04,
    QUIC_FLOW_BLOCKED_CONGESTION_CONTROL    = 0x08,
    QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL     = 0x10,
    QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL= 0x20,
    QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL   = 0x40,
    QUIC_FLOW_BLOCKED_APP                   = 0x80
} QUIC_FLOW_BLOCK_REASON;

typedef enum QUIC_TRACE_PACKET_TYPE {
    QUIC_TRACE_PACKET_VN,
    QUIC_TRACE_PACKET_INITIAL,
    QUIC_TRACE_PACKET_ZERO_RTT,
    QUIC_TRACE_PACKET_HANDSHAKE,
    QUIC_TRACE_PACKET_RETRY,
    QUIC_TRACE_PACKET_ONE_RTT
} QUIC_TRACE_PACKET_TYPE;

typedef enum QUIC_TRACE_PACKET_LOSS_REASON {
    QUIC_TRACE_PACKET_LOSS_RACK,
    QUIC_TRACE_PACKET_LOSS_FACK,
    QUIC_TRACE_PACKET_LOSS_PROBE
} QUIC_TRACE_PACKET_LOSS_REASON;

typedef enum QUIC_TRACE_API_TYPE {
    QUIC_TRACE_API_SET_PARAM,
    QUIC_TRACE_API_GET_PARAM,
    QUIC_TRACE_API_REGISTRATION_OPEN,
    QUIC_TRACE_API_REGISTRATION_CLOSE,
    QUIC_TRACE_API_REGISTRATION_SHUTDOWN,
    QUIC_TRACE_API_CONFIGURATION_OPEN,
    QUIC_TRACE_API_CONFIGURATION_CLOSE,
    QUIC_TRACE_API_CONFIGURATION_LOAD_CREDENTIAL,
    QUIC_TRACE_API_LISTENER_OPEN,
    QUIC_TRACE_API_LISTENER_CLOSE,
    QUIC_TRACE_API_LISTENER_START,
    QUIC_TRACE_API_LISTENER_STOP,
    QUIC_TRACE_API_CONNECTION_OPEN,
    QUIC_TRACE_API_CONNECTION_CLOSE,
    QUIC_TRACE_API_CONNECTION_SHUTDOWN,
    QUIC_TRACE_API_CONNECTION_START,
    QUIC_TRACE_API_CONNECTION_SET_CONFIGURATION,
    QUIC_TRACE_API_CONNECTION_SEND_RESUMPTION_TICKET,
    QUIC_TRACE_API_STREAM_OPEN,
    QUIC_TRACE_API_STREAM_CLOSE,
    QUIC_TRACE_API_STREAM_START,
    QUIC_TRACE_API_STREAM_SHUTDOWN,
    QUIC_TRACE_API_STREAM_SEND,
    QUIC_TRACE_API_STREAM_RECEIVE_COMPLETE,
    QUIC_TRACE_API_STREAM_RECEIVE_SET_ENABLED,
    QUIC_TRACE_API_DATAGRAM_SEND,
    QUIC_TRACE_API_COUNT // Must be last
} QUIC_TRACE_API_TYPE;

typedef enum QUIC_TRACE_LEVEL {
    QUIC_TRACE_LEVEL_DEV,
    QUIC_TRACE_LEVEL_VERBOSE,
    QUIC_TRACE_LEVEL_INFO,
    QUIC_TRACE_LEVEL_WARNING,
    QUIC_TRACE_LEVEL_ERROR,
    QUIC_TRACE_LEVEL_PACKET_VERBOSE,
    QUIC_TRACE_LEVEL_PACKET_INFO,
    QUIC_TRACE_LEVEL_PACKET_WARNING
} QUIC_TRACE_LEVEL;

//
// Called from the platform code to trigger a tracing rundown for all objects
// in the current process (or kernel mode).
//

//#if defined(QUIC_EVENTS_STUB) || defined(QUIC_LOGS_STUB)
//#include <syslog.h>
//#endif 


#ifdef __cplusplus
extern "C"
#endif
typedef
_Function_class_(QUIC_TRACE_RUNDOWN_CALLBACK)
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_TRACE_RUNDOWN_CALLBACK)(
    void
    );

extern QUIC_TRACE_RUNDOWN_CALLBACK* QuicTraceRundownCallback;



#ifdef QUIC_CLOG
#define QuicTraceLogStreamVerboseEnabled() TRUE
#define QuicTraceLogErrorEnabled()   TRUE
#define QuicTraceLogWarningEnabled() TRUE
#define QuicTraceLogInfoEnabled()    TRUE
#define QuicTraceLogVerboseEnabled() TRUE
#define QuicTraceEventEnabled(x)     TRUE

#else

#ifdef QUIC_EVENTS_STUB
#define QuicTraceEventEnabled(Name)  FALSE

inline
void
QuicTraceEventStubVarArgs(
    _In_ const void* Fmt,
    ...
    )
{
    UNREFERENCED_PARAMETER(Fmt);
}

#define QuicTraceEvent(...)          syslog(LOG_ERR, __VA_ARGS__) 
#endif // QUIC_EVENTS_STUB


#ifdef QUIC_EVENTS_MANIFEST_ETW
#include <evntprov.h>

#ifdef __cplusplus
extern "C"
#endif
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
void
NTAPI
QuicEtwCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG ControlCode,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _Inout_opt_ PVOID CallbackContext
    );

//
// Defining MCGEN_PRIVATE_ENABLE_CALLBACK_V2, makes McGenControlCallbackV2
// call our user-defined callback routine. See MsQuicEvents.h.
//
#define MCGEN_PRIVATE_ENABLE_CALLBACK_V2 QuicEtwCallback

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#pragma warning(disable:26451)
#include "MsQuicEtw.h"
#pragma warning(pop)

#define QuicTraceEventEnabled(Name) EventEnabledQuic##Name()
#define _QuicTraceEvent(Name, Args) EventWriteQuic##Name##Args
#define QuicTraceEvent(...) 
#endif // QUIC_EVENTS_MANIFEST_ETW



#ifdef QUIC_LOGS_STUB
#include <syslog.h>

#define QuicTraceLogErrorEnabled()   FALSE
#define QuicTraceLogWarningEnabled() FALSE
#define QuicTraceLogInfoEnabled()    FALSE
#define QuicTraceLogVerboseEnabled() FALSE

#define QuicTraceLogError(...)            syslog(LOG_ERR, __VA_ARGS__)
#define QuicTraceLogWarning(...)          syslog(LOG_WARNING, __VA_ARGS__)
#define QuicTraceLogInfo(...)             syslog(LOG_INFO, __VA_ARGS__)
#define QuicTraceLogVerbose(...)          syslog(LOG_DEBUG, __VA_ARGS__)

#define QuicTraceLogConnError(...)        syslog(LOG_ERR, __VA_ARGS__)
#define QuicTraceLogConnWarning(...)      syslog(LOG_WARNING, __VA_ARGS__)
#define QuicTraceLogConnInfo(...)         syslog(LOG_INFO, __VA_ARGS__)
#define QuicTraceLogConnVerbose(...)      syslog(LOG_DEBUG, __VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() FALSE

#define QuicTraceLogStreamError(...)      syslog(LOG_ERR, __VA_ARGS__)
#define QuicTraceLogStreamWarning(...)    syslog(LOG_WARNING, __VA_ARGS__)
#define QuicTraceLogStreamInfo(...)       syslog(LOG_INFO, __VA_ARGS__)
#define QuicTraceLogStreamVerbose(...)    syslog(LOG_DEBUG, __VA_ARGS__)
#define QuicTraceLogSetDebug(level)       (setlogmask(LOG_UPTO(level)))
#endif // QUIC_LOGS_STUB


#ifdef QUIC_LOGS_MANIFEST_ETW

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#pragma warning(disable:26451)
#include "MsQuicEtw.h"
#include <syslog.h>
#pragma warning(pop)

#include <stdio.h>

#define QuicTraceLogErrorEnabled()   EventEnabledQuicLogError()
#define QuicTraceLogWarningEnabled() EventEnabledQuicLogWarning()
#define QuicTraceLogInfoEnabled()    EventEnabledQuicLogInfo()
#define QuicTraceLogVerboseEnabled() EventEnabledQuicLogVerbose()

#define QUIC_ETW_BUFFER_LENGTH 128

#define LogEtw(EventName, Fmt, ...) \
    if (EventEnabledQuicLog##EventName()) { \
        char EtwBuffer[QUIC_ETW_BUFFER_LENGTH]; \
        _snprintf_s(EtwBuffer, sizeof(EtwBuffer), _TRUNCATE, Fmt, ##__VA_ARGS__); \
        EventWriteQuicLog##EventName##_AssumeEnabled(EtwBuffer); \
    }

#define LogEtwType(Type, EventName, Ptr, Fmt, ...) \
    if (EventEnabledQuic##Type##Log##EventName()) { \
        char EtwBuffer[QUIC_ETW_BUFFER_LENGTH]; \
        _snprintf_s(EtwBuffer, sizeof(EtwBuffer), _TRUNCATE, Fmt, ##__VA_ARGS__); \
        EventWriteQuic##Type##Log##EventName##_AssumeEnabled(Ptr, EtwBuffer); \
    }

#define QuicTraceLogError(Name, Fmt, ...)               syslog(Error, __VA_ARGS__)
#define QuicTraceLogWarning(Name, Fmt, ...)             syslog(Warning, __VA_ARGS__)
#define QuicTraceLogInfo(Name, Fmt, ...)                syslog(Info, __VA_ARGS__)
#define QuicTraceLogVerbose(Name, Fmt, ...)             syslog(Verbose, __VA_ARGS__)

#define QuicTraceLogConnError(Name, Ptr, Fmt, ...)      syslog(Error, __VA_ARGS__)
#define QuicTraceLogConnWarning(Name, Ptr, Fmt, ...)    syslog(Warning, __VA_ARGS__)
#define QuicTraceLogConnInfo(Name, Ptr, Fmt, ...)       syslog(Info, __VA_ARGS__)
#define QuicTraceLogConnVerbose(Name, Ptr, Fmt, ...)    syslog(verbose, __VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() EventEnabledQuicStreamLogVerbose()

#define QuicTraceLogStreamError(Name, Ptr, Fmt, ...)    syslog(Error, __VA_ARGS__)
#define QuicTraceLogStreamWarning(Name, Ptr, Fmt, ...)  syslog(Warning, __VA_ARGS__)
#define QuicTraceLogStreamInfo(Name, Ptr, Fmt, ...)     syslog(Info, __VA_ARGS__)
#define QuicTraceLogStreamVerbose(Name, Ptr, Fmt, ...)  syslog(Verbose, __VA_ARGS__)

#endif // QUIC_LOGS_MANIFEST_ETW

#endif // QUIC_CLOG
