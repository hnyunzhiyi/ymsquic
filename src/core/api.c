/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This module provides the implementation for most of the MsQuic* APIs.

--*/
#include "precomp.h"
#include <unistd.h>
#include <fcntl.h>

//#define IO_SIZE (128 * 1024)
#define IO_SIZE 32

#define IS_REGISTRATION_HANDLE(Handle) \
( \
    (Handle) != NULL && (Handle)->Type == QUIC_HANDLE_TYPE_REGISTRATION \
)

#define IS_CONN_HANDLE(Handle) \
( \
    (Handle) != NULL && \
    ((Handle)->Type == QUIC_HANDLE_TYPE_CONNECTION_CLIENT || (Handle)->Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER) \
)

#define IS_STREAM_HANDLE(Handle) \
( \
    (Handle) != NULL && (Handle)->Type == QUIC_HANDLE_TYPE_STREAM \
)

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionOpen(
    _In_ _Pre_defensive_ HQUIC RegistrationHandle,
    _In_ _Pre_defensive_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*NewConnection, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *NewConnection
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_CONNECTION* Connection = NULL;

    QuicTraceLogVerbose(
        "ApiEnter: [ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_OPEN,
        RegistrationHandle);

    if (!IS_REGISTRATION_HANDLE(RegistrationHandle) ||
        NewConnection == NULL ||
        Handler == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Registration = (QUIC_REGISTRATION*)RegistrationHandle;

    if ((Connection = QuicConnAlloc(Registration, NULL)) == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Connection->ClientCallbackHandler = Handler;
    Connection->ClientContext = Context;
	Connection->Attribute = NULL;

    QuicRegistrationQueueNewConnection(Registration, Connection);
	
    *NewConnection = (HQUIC)Connection;
    Status = QUIC_STATUS_SUCCESS;

Error:
   if (Status != QUIC_STATUS_SUCCESS){
        QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
   }
    return Status;
}

#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't understand the free happens on the worker
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicConnectionClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    QUIC_CONNECTION* Connection;

    QUIC_PASSIVE_CODE();

    QuicTraceLogVerbose(
        "ApiEnter: [api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_CLOSE,
        Handle);

    if (!IS_CONN_HANDLE(Handle)) {
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Connection = (QUIC_CONNECTION*)Handle;

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);
    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Connection->WorkerThreadID == QuicCurThreadID()) {
		BOOLEAN AlreadyInline = Connection->State.InlineApiExecution;
        if (!AlreadyInline) {
            Connection->State.InlineApiExecution = TRUE;
        }

        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        QuicConnCloseHandle(Connection);
		if (!AlreadyInline) {
			Connection->State.InlineApiExecution = FALSE;
		}

    } else {

        QUIC_EVENT CompletionEvent;
        QUIC_OPERATION Oper;
		QuicZeroMemory(&Oper, sizeof(QUIC_OPERATION));
        QUIC_API_CONTEXT ApiCtx;

        Oper.Type = QUIC_OPER_TYPE_API_CALL;
        Oper.FreeAfterProcess = FALSE;
        Oper.API_CALL.Context = &ApiCtx;

        ApiCtx.Type = QUIC_API_TYPE_CONN_CLOSE;
        QuicEventInitialize(&CompletionEvent, TRUE, FALSE);
        ApiCtx.Completed = &CompletionEvent;
        ApiCtx.Status = NULL;

        //
        // Queue the operation and wait for it to be processed.
        //
        QuicConnQueueOper(Connection, &Oper);
        QuicTraceLogVerbose("ApiWaitOperation: [api] Waiting on operation");
        QuicEventWaitForever(CompletionEvent);
        QuicEventUninitialize(CompletionEvent);
    }

    //
    // Connection can only be released by the application after the released
    // flag was set, in response to the CONN_CLOSE operation was processed.
    //
    QUIC_TEL_ASSERT(Connection->State.HandleClosed);

    //
    // Release the reference to the Connection.
    //
    QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);

Error:

    QuicTraceLogVerbose("ApiExit: [api] Exit");
}
#pragma warning(pop)

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicConnectionShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    )
{
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;


    QuicTraceLogVerbose(
        "ApiEnter: [ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_SHUTDOWN,
        Handle);

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
        QUIC_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        goto Error;
    }

    if (ErrorCode > QUIC_UINT62_MAX) {
        QUIC_CONN_VERIFY(Connection, ErrorCode <= QUIC_UINT62_MAX);
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == QuicCurThreadID()) ||
        !Connection->State.HandleClosed);

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        if (InterlockedCompareExchange16(
                (short*)&Connection->BackUpOperUsed, 1, 0) != 0) {
            goto Error; // It's already started the shutdown.
        }
        Oper = &Connection->BackUpOper;
        Oper->FreeAfterProcess = FALSE;
        Oper->Type = QUIC_OPER_TYPE_API_CALL;
        Oper->API_CALL.Context = &Connection->BackupApiContext;
    }
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SHUTDOWN;
    Oper->API_CALL.Context->CONN_SHUTDOWN.Flags = Flags;
    Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode = ErrorCode;

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueHighestPriorityOper(Connection, Oper);
    
Error:
    QuicTraceLogVerbose("ApiExit: ConnectionShutdown:[api] Exit");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ HQUIC ConfigHandle,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_opt_z_(QUIC_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;
    QUIC_CONFIGURATION* Configuration;
    QUIC_OPERATION* Oper;
    char* ServerNameCopy = NULL;



    QuicTraceLogVerbose(
        "ApiEnter: [ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_START,
        Handle);

    if (ConfigHandle == NULL ||
        ConfigHandle->Type != QUIC_HANDLE_TYPE_CONFIGURATION ||
        ServerPort == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    //
    // Make sure the connection is to a IPv4 or IPv6 address or unspecified.
    //
    if (Family != QUIC_ADDRESS_FAMILY_UNSPEC &&
        Family != QUIC_ADDRESS_FAMILY_INET &&
        Family != QUIC_ADDRESS_FAMILY_INET6) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
        QUIC_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (QuicConnIsServer(Connection) ||
        (!Connection->State.RemoteAddressSet && ServerName == NULL)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Connection->State.Started || Connection->State.ClosedLocally) {
        Status = QUIC_STATUS_INVALID_STATE; // TODO - Support the Connect after close/previous connect failure?
        goto Error;
    }

    Configuration = (QUIC_CONFIGURATION*)ConfigHandle;

    if (Configuration->SecurityConfig == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (ServerName != NULL) {
        //
        // Validate the server name length.
        //
        size_t ServerNameLength = strnlen(ServerName, QUIC_MAX_SNI_LENGTH + 1);
        if (ServerNameLength == QUIC_MAX_SNI_LENGTH + 1) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }

        //
        // Allocate copy of the server name, to save with the connection.
        //
#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed by the connection.")
        ServerNameCopy = QUIC_ALLOC_NONPAGED(ServerNameLength + 1);
        if (ServerNameCopy == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceLogError(
                "AllocFailure: Allocation of '%s' failed. (%lu bytes)",
                "Server name",
                ServerNameLength + 1);
            goto Error;
        }

        QuicCopyMemory(ServerNameCopy, ServerName, ServerNameLength);
        ServerNameCopy[ServerNameLength] = 0;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);
    QUIC_DBG_ASSERT(QuicConnIsClient(Connection));
    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError(
            "AllocFailure: Allocation of '%s' failed. (%u bytes)",
            "CONN_START operation",
            0);
        goto Error;
    }

    QuicConfigurationAddRef(Configuration);
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_START;
    Oper->API_CALL.Context->CONN_START.Configuration = Configuration;
    Oper->API_CALL.Context->CONN_START.ServerName = ServerNameCopy;
    Oper->API_CALL.Context->CONN_START.ServerPort = ServerPort;
    Oper->API_CALL.Context->CONN_START.Family = Family;
    ServerNameCopy = NULL;

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_PENDING;

Error:

    if (ServerNameCopy != NULL) {
        QUIC_FREE(ServerNameCopy);
    }
		QuicTraceLogInfo("ApiExitStatus: [ api] Exit %u", Status);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionSetConfiguration(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ HQUIC ConfigHandle
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;
    QUIC_CONFIGURATION* Configuration;
    QUIC_OPERATION* Oper;

    QuicTraceLogVerbose(
        "ApiEnter: [ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_SET_CONFIGURATION,
        Handle);

    if (ConfigHandle == NULL ||
        ConfigHandle->Type != QUIC_HANDLE_TYPE_CONFIGURATION) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
        QUIC_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (QuicConnIsClient(Connection)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Connection->Configuration != NULL) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    Configuration = (QUIC_CONFIGURATION*)ConfigHandle;

    if (Configuration->SecurityConfig == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);
    QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError(
            "AllocFailure: Allocation of '%s' failed. (%u bytes)",
            "CONN_SET_CONFIGURATION operation",
            0);
        goto Error;
    }

    QuicConfigurationAddRef(Configuration);
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SET_CONFIGURATION;
    Oper->API_CALL.Context->CONN_SET_CONFIGURATION.Configuration = Configuration;

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_PENDING;

Error:

    if (Status != QUIC_STATUS_PENDING){
    	QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionSendResumptionTicket(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_SEND_RESUMPTION_FLAGS Flags,
    _In_ uint16_t DataLength,
    _In_reads_bytes_opt_(DataLength)
        const uint8_t* ResumptionData
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;
    uint8_t* ResumptionDataCopy = NULL;



    QuicTraceLogVerbose(
        "ApiEnter: [api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_SEND_RESUMPTION_TICKET,
        Handle);

    if (DataLength > QUIC_MAX_RESUMPTION_APP_DATA_LENGTH ||
        (ResumptionData == NULL && DataLength != 0)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Flags > (QUIC_SEND_RESUMPTION_FLAG_FINAL | QUIC_SEND_RESUMPTION_FLAG_NONE)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
        QUIC_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

    if (QuicConnIsClient(Connection)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (!Connection->State.ResumptionEnabled ||
        !Connection->State.Connected ||
        !Connection->Crypto.TlsState.HandshakeComplete) {
        Status = QUIC_STATUS_INVALID_STATE; // TODO - Support queueing up the ticket to send once connected.
        goto Error;
    }

    if (DataLength > 0) {
        ResumptionDataCopy = QUIC_ALLOC_NONPAGED(DataLength);
        if (ResumptionDataCopy == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceLogError(
                "AllocFailure: Allocation of '%s' failed. (%u bytes)",
                "Resumption data copy",
                DataLength);
            goto Error;
        }
        QuicCopyMemory(ResumptionDataCopy, ResumptionData, DataLength);
    }

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError(
            "AllocFailure: Allocation of '%s' failed. (%u bytes)",
            "CONN_SEND_RESUMPTION_TICKET operation",
            0);
        goto Error;
    }
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET;
    Oper->API_CALL.Context->CONN_SEND_RESUMPTION_TICKET.Flags = Flags;
    Oper->API_CALL.Context->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData = ResumptionDataCopy;
    Oper->API_CALL.Context->CONN_SEND_RESUMPTION_TICKET.AppDataLength = DataLength;

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_SUCCESS;
    ResumptionDataCopy = NULL;

Error:

    if (ResumptionDataCopy != NULL) {
        QUIC_FREE(ResumptionDataCopy);
    }

    if( Status != QUIC_STATUS_SUCCESS){
    	QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
	}
    
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamOpen(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_STREAM_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*NewStream, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC *NewStream
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;

    QuicTraceLogVerbose(
        "ApiEnter: [ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_OPEN,
        Handle);

    if (NewStream == NULL ||
        Handler == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (IS_CONN_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else if (IS_STREAM_HANDLE(Handle)) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_STREAM* Stream = (QUIC_STREAM*)Handle;
        QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
        QUIC_TEL_ASSERT(!Stream->Flags.Freed);
        Connection = Stream->Connection;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    BOOLEAN ClosedLocally = Connection->State.ClosedLocally;
    if (ClosedLocally || Connection->State.ClosedRemotely) {
        Status =
            ClosedLocally ?
            QUIC_STATUS_INVALID_STATE :
            QUIC_STATUS_ABORTED;
        goto Error;
    }

    Status =
        QuicStreamInitialize(
            Connection,
            FALSE,
            !!(Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL),
            !!(Flags & QUIC_STREAM_OPEN_FLAG_0_RTT),
            (QUIC_STREAM**)NewStream);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    (*(QUIC_STREAM**)NewStream)->ClientCallbackHandler = Handler;
    (*(QUIC_STREAM**)NewStream)->ClientContext = Context;

Error:

    if(QUIC_FAILED(Status)){ 
        QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

#pragma warning(push)
#pragma warning(disable:6014) // SAL doesn't understand the free happens on the worker
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicStreamClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;

    QUIC_PASSIVE_CODE();

    QuicTraceLogVerbose(
        "ApiEnter: [ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_CLOSE,
        Handle);

    if (!IS_STREAM_HANDLE(Handle)) {
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
    QUIC_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Connection->WorkerThreadID == QuicCurThreadID()) {
        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        BOOLEAN AlreadyInline = Connection->State.InlineApiExecution;
        if (!AlreadyInline) {
            Connection->State.InlineApiExecution = TRUE;
        }
        QuicStreamClose(Stream);
        if (!AlreadyInline) {
            Connection->State.InlineApiExecution = FALSE;
        }

    } else {

        QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

        BOOLEAN AlreadyShutdownComplete = Stream->ClientCallbackHandler == NULL;
        if (AlreadyShutdownComplete) {
            //
            // No need to wait for the close if already shutdown complete.
            //
            QUIC_OPERATION* Oper =
                QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
            if (Oper != NULL) {
                Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_CLOSE;
                Oper->API_CALL.Context->STRM_CLOSE.Stream = Stream;
                QuicConnQueueOper(Connection, Oper);
                goto Error;
            }
        }

        QUIC_EVENT CompletionEvent;
        QUIC_OPERATION Oper;
        QuicZeroMemory(&Oper, sizeof(QUIC_OPERATION));
        QUIC_API_CONTEXT ApiCtx;

        Oper.Type = QUIC_OPER_TYPE_API_CALL;
        Oper.FreeAfterProcess = FALSE;
        Oper.API_CALL.Context = &ApiCtx;

        ApiCtx.Type = QUIC_API_TYPE_STRM_CLOSE;
        QuicEventInitialize(&CompletionEvent, TRUE, FALSE);
        ApiCtx.Completed = &CompletionEvent;
        ApiCtx.Status = NULL;
        ApiCtx.STRM_CLOSE.Stream = Stream;

        //
        // Queue the operation and wait for it to be processed.
        //
        QuicConnQueueOper(Connection, &Oper);
        QuicTraceLogVerbose("ApiWaitOperation: [api] Waiting on operation");
        QuicEventWaitForever(CompletionEvent);
        QuicEventUninitialize(CompletionEvent);
    }
Error:
	QuicTraceLogInfo("[ api] Exit");

}
#pragma warning(pop)
_When_(Flags & QUIC_STREAM_START_FLAG_ASYNC, _IRQL_requires_max_(DISPATCH_LEVEL))
_When_(!(Flags & QUIC_STREAM_START_FLAG_ASYNC), _IRQL_requires_max_(PASSIVE_LEVEL))


QUIC_STATUS
QUIC_API
MsQuicStreamStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_START_FLAGS Flags
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;

    QuicTraceLogVerbose("ApiEnter: [api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_START,
        Handle);

    if (!IS_STREAM_HANDLE(Handle)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
    QUIC_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Stream->Flags.Started) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

	if (Flags & QUIC_STREAM_START_FLAG_ASYNC) {
        QUIC_OPERATION* Oper =
            QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
        if (Oper == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceLogError(
                "AllocFailure: Allocation of '%s' failed. (%u bytes)",
                "STRM_START operation",
                0);
            goto Exit;
        }
        Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_START;
        Oper->API_CALL.Context->STRM_START.Stream = Stream;
        Oper->API_CALL.Context->STRM_START.Flags = Flags;

        //
        // Async stream operations need to hold a ref on the stream so that the
        // stream isn't freed before the operation can be processed. The ref is
        // released after the operation is processed.
        //
        QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

        //
        // Queue the operation but don't wait for the completion.
        //
        QuicConnQueueOper(Connection, Oper);
        Status = QUIC_STATUS_PENDING;

    } else if (Connection->WorkerThreadID == QuicCurThreadID()) { 
		QUIC_PASSIVE_CODE();
        //
        //Execute this blocking API call inline if called on the worker thread.
        //           		
        BOOLEAN AlreadyInline = Connection->State.InlineApiExecution;
        if (!AlreadyInline) {
            Connection->State.InlineApiExecution = TRUE;
        }
        Status = QuicStreamStart(Stream, Flags, FALSE);
        if (!AlreadyInline) {
            Connection->State.InlineApiExecution = FALSE;
        }		

	} else {

		QUIC_PASSIVE_CODE();
        QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

        QUIC_EVENT CompletionEvent;
        QUIC_OPERATION Oper;
        QuicZeroMemory(&Oper, sizeof(QUIC_OPERATION));
        QUIC_API_CONTEXT ApiCtx;

        Oper.Type = QUIC_OPER_TYPE_API_CALL;
        Oper.FreeAfterProcess = FALSE;
        Oper.API_CALL.Context = &ApiCtx;

        ApiCtx.Type = QUIC_API_TYPE_STRM_START;
        QuicEventInitialize(&CompletionEvent, TRUE, FALSE);
        ApiCtx.Completed = &CompletionEvent;
        ApiCtx.Status = &Status;
        ApiCtx.STRM_START.Stream = Stream;
        ApiCtx.STRM_START.Flags = Flags;

        //
        // Queue the operation and wait for it to be processed.
        //
        QuicConnQueueOper(Connection, &Oper);
        QuicTraceLogVerbose("ApiWaitOperation: [api] Waiting on operation");
        QuicEventWaitForever(CompletionEvent);
        QuicEventUninitialize(CompletionEvent);
    }

Exit:

    if (QUIC_FAILED(Status)){
        QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;

    QuicTraceLogVerbose("ApiEnter: [ api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_SHUTDOWN,
        Handle);

    if (!IS_STREAM_HANDLE(Handle) ||
        Flags == 0 || Flags == QUIC_STREAM_SHUTDOWN_SILENT) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (ErrorCode > QUIC_UINT62_MAX) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Flags & QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL &&
        Flags != QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL) {
        //
        // Not allowed to use the graceful shutdown flag with any other flag.
        //
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Flags & QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE &&
        Flags != (QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND)) {
        //
        // Immediate shutdown requires both directions to be aborted.
        //
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
    QUIC_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection, Connection->State.HandleClosed);

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError("AllocFailure: Allocation of '%s' failed. (%u bytes)",
            "STRM_SHUTDOWN operation",
            0);
        goto Error;
    }
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_SHUTDOWN;
    Oper->API_CALL.Context->STRM_SHUTDOWN.Stream = Stream;
    Oper->API_CALL.Context->STRM_SHUTDOWN.Flags = Flags;
    Oper->API_CALL.Context->STRM_SHUTDOWN.ErrorCode = ErrorCode;

    //
    // Async stream operations need to hold a ref on the stream so that the
    // stream isn't freed before the operation can be processed. The ref is
    // released after the operation is processed.
    //
    QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_PENDING;

Error:

    if (Status != QUIC_STATUS_PENDING){
        QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamSend(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_reads_(BufferCount) _Pre_defensive_
        const QUIC_BUFFER * const Buffers,
    _In_ uint32_t BufferCount,
    _In_ QUIC_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;
    uint64_t TotalLength;
    QUIC_SEND_REQUEST* SendRequest;
    BOOLEAN QueueOper = TRUE;
    QUIC_OPERATION* Oper;

    QuicTraceLogVerbose("ApiEnter: [api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_SEND,
        Handle);

    if (!IS_STREAM_HANDLE(Handle) ||
        (Buffers == NULL &&
        BufferCount != 0)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
    QUIC_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == QuicCurThreadID()) ||
        !Connection->State.HandleClosed);

    TotalLength = 0;
    for (uint32_t i = 0; i < BufferCount; ++i) {
        TotalLength += Buffers[i].Length;
    }

    if (TotalLength > UINT32_MAX) {
        QuicTraceLogError("StreamError: [strm][%p] ERROR, %s.",
            Stream,
            "Send request total length exceeds max");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (QuicStreamCompleteSendRequest).")
    SendRequest = QuicPoolAlloc(&Connection->Worker->SendRequestPool);
    if (SendRequest == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceLogError("AllocFailure: Allocation of '%s' failed. (%u bytes)",
            "Stream Send request",
            0);
        goto Exit;
    }

    SendRequest->Next = NULL;
    SendRequest->Buffers = Buffers;
    SendRequest->BufferCount = BufferCount;
    SendRequest->Flags = Flags & ~QUIC_SEND_FLAGS_INTERNAL;
    SendRequest->TotalLength = TotalLength;
    SendRequest->ClientContext = ClientSendContext;

    QuicDispatchLockAcquire(&Stream->ApiSendRequestLock);
    if (!Stream->Flags.SendEnabled) {
        Status = QUIC_STATUS_INVALID_STATE;
    } else {
        QUIC_SEND_REQUEST** ApiSendRequestsTail = &Stream->ApiSendRequests;
        while (*ApiSendRequestsTail != NULL) {
            ApiSendRequestsTail = &((*ApiSendRequestsTail)->Next);
            QueueOper = FALSE; // Not necessary if the previous send hasn't been flushed yet.
        }
        *ApiSendRequestsTail = SendRequest;
        Status = QUIC_STATUS_SUCCESS;
    }
    QuicDispatchLockRelease(&Stream->ApiSendRequestLock);

    if (QUIC_FAILED(Status)) {
        QuicPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
        goto Exit;
    }

    if (QueueOper) {
        Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
        if (Oper == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceLogError("AllocFailure: Allocation of '%s' failed. (%u bytes)",
                "STRM_SEND operation",
                0);
            goto Exit;
        }
        Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_SEND;
        Oper->API_CALL.Context->STRM_SEND.Stream = Stream;

        //
        // Async stream operations need to hold a ref on the stream so that the
        // stream isn't freed before the operation can be processed. The ref is
        // released after the operation is processed.
        //
        QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

        //
        // Queue the operation but don't wait for the completion.
        //
        QuicConnQueueOper(Connection, Oper);
    }

    Status = QUIC_STATUS_PENDING;

Exit:
    if (Status != QUIC_STATUS_PENDING){
        QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamReceiveSetEnabled(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ BOOLEAN IsEnabled
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;

    QuicTraceLogVerbose("ApiEnter: [api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_RECEIVE_SET_ENABLED,
        Handle);

    if (!IS_STREAM_HANDLE(Handle)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
    QUIC_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == QuicCurThreadID()) ||
        !Connection->State.HandleClosed);

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError("AllocFailure: Allocation of '%s' failed. (%u bytes)",
            "STRM_RECV_SET_ENABLED, operation",
            0);
        goto Error;
    }
    Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_RECV_SET_ENABLED;
    Oper->API_CALL.Context->STRM_RECV_SET_ENABLED.Stream = Stream;
    Oper->API_CALL.Context->STRM_RECV_SET_ENABLED.IsEnabled = IsEnabled;

    //
    // Async stream operations need to hold a ref on the stream so that the
    // stream isn't freed before the operation can be processed. The ref is
    // released after the operation is processed.
    //
    QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_PENDING;

Error:
    if (Status != QUIC_STATUS_PENDING){
        QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamReceiveComplete(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ uint64_t BufferLength
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    QUIC_CONNECTION* Connection;
    QUIC_OPERATION* Oper;

    QuicTraceLogVerbose("ApiEnter: [api] Enter %u (%p).",
        QUIC_TRACE_API_STREAM_RECEIVE_COMPLETE,
        Handle);

    if (!IS_STREAM_HANDLE(Handle)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Stream = (QUIC_STREAM*)Handle;

    QUIC_TEL_ASSERT(!Stream->Flags.HandleClosed);
    QUIC_TEL_ASSERT(!Stream->Flags.Freed);

    Connection = Stream->Connection;

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);
    QUIC_CONN_VERIFY(Connection,
        (Connection->WorkerThreadID == QuicCurThreadID()) ||
        !Connection->State.HandleClosed);

    if (!Stream->Flags.Started || !Stream->Flags.ReceiveCallPending) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_API_CALL);
    if (Oper == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError("AllocFailure: Allocation of '%s' failed. (%u bytes)",
            "STRM_RECV_COMPLETE operation",
            0);
        goto Exit;
    }

    Oper->API_CALL.Context->Type = QUIC_API_TYPE_STRM_RECV_COMPLETE;
    Oper->API_CALL.Context->STRM_RECV_COMPLETE.Stream = Stream;
    Oper->API_CALL.Context->STRM_RECV_COMPLETE.BufferLength = BufferLength;

    //
    // Async stream operations need to hold a ref on the stream so that the
    // stream isn't freed before the operation can be processed. The ref is
    // released after the operation is processed.
    //
    QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);

    //
    // Queue the operation but don't wait for the completion.
    //
    QuicConnQueueOper(Connection, Oper);
    Status = QUIC_STATUS_SUCCESS;

Exit:
    if(Status != QUIC_STATUS_SUCCESS){
        QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

#define QUIC_PARAM_GENERATOR(Level, Value) (((Level + 1) & 0x3F) << 26 | (Value & 0x3FFFFFF))

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicSetParam(
    _When_(Level == QUIC_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != QUIC_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_PASSIVE_CODE();

    if ((Param & 0xFC000000) != 0) {
        //
        //Has level embedded parameter. Validate matches passed in level.
        //             
        QUIC_PARAM_LEVEL ParamContainedLevel = ((Param >> 26) & 0x3F) - 1;
        if (ParamContainedLevel != Level) {
            QuicTraceLogError(
                "[ lib] ERROR, %s.",
                "Param level does not match param value");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else {
        //
        //Missing level embedded parameter. Inject level into parameter.
        //      
        Param = QUIC_PARAM_GENERATOR(Level, Param);
    }

    if ((Handle == NULL) ^ (Level == QUIC_PARAM_LEVEL_GLOBAL)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QuicTraceLogVerbose("ApiEnter: [ api] Enter %u (%p).",
        QUIC_TRACE_API_SET_PARAM,
        Handle);

    QUIC_STATUS Status;

    if (Level == QUIC_PARAM_LEVEL_GLOBAL) {
        //
        // Global parameters are processed inline.
        //
        Status = QuicLibrarySetGlobalParam(Param, BufferLength, Buffer);
        goto Error;
    }

    if (Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION ||
        Handle->Type == QUIC_HANDLE_TYPE_CONFIGURATION ||
        Handle->Type == QUIC_HANDLE_TYPE_LISTENER) {
        //
        // Registration, Configuration and Listener parameters are processed inline.
        //
        Status = QuicLibrarySetParam(Handle, Level, Param, BufferLength, Buffer);
        goto Error;
    }

    QUIC_CONNECTION* Connection;
    QUIC_EVENT CompletionEvent;

    if (Handle->Type == QUIC_HANDLE_TYPE_STREAM) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = ((QUIC_STREAM*)Handle)->Connection;
    } else if (Handle->Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER ||
        Handle->Type == QUIC_HANDLE_TYPE_CONNECTION_CLIENT) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Connection->WorkerThreadID == QuicCurThreadID()) {
        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        BOOLEAN AlreadyInline = Connection->State.InlineApiExecution;
        if (!AlreadyInline) {
            Connection->State.InlineApiExecution = TRUE;
        }		
        Status = QuicLibrarySetParam(Handle, Level, Param, BufferLength, Buffer);
        if (!AlreadyInline) {
            Connection->State.InlineApiExecution = FALSE;
        }	
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

    QUIC_OPERATION Oper;
    QuicZeroMemory(&Oper, sizeof(QUIC_OPERATION));
    QUIC_API_CONTEXT ApiCtx;

    Oper.Type = QUIC_OPER_TYPE_API_CALL;
    Oper.FreeAfterProcess = FALSE;
    Oper.API_CALL.Context = &ApiCtx;

    ApiCtx.Type = QUIC_API_TYPE_SET_PARAM;
    QuicEventInitialize(&CompletionEvent, TRUE, FALSE);
    ApiCtx.Completed = &CompletionEvent;
    ApiCtx.Status = &Status;
    ApiCtx.SET_PARAM.Handle = Handle;
    ApiCtx.SET_PARAM.Level = Level;
    ApiCtx.SET_PARAM.Param = Param;
    ApiCtx.SET_PARAM.BufferLength = BufferLength;
    ApiCtx.SET_PARAM.Buffer = Buffer;

    //
    // Queue the operation and wait for it to be processed.
    //
    QuicConnQueueOper(Connection, &Oper);
    QuicTraceLogVerbose("ApiWaitOperation: [api] Waiting on operation");
    QuicEventWaitForever(CompletionEvent);
    QuicEventUninitialize(CompletionEvent);

Error:

    if(QUIC_FAILED(Status)){ 
        QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicGetParam(
    _When_(Level == QUIC_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != QUIC_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ _Pre_defensive_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_PASSIVE_CODE();

	if ((Param & 0xFC000000) != 0) {
        //
        //Has level embedded parameter. Validate matches passed in level.
        //            			
        QUIC_PARAM_LEVEL ParamContainedLevel = ((Param >> 26) & 0x3F) - 1;
        if (ParamContainedLevel != Level) {
            QuicTraceLogError(
                "[ lib] ERROR, %s.",
                "Param level does not match param value");
            return QUIC_STATUS_INVALID_PARAMETER;
        }				
	} else {
        //
        //Missing level embedded parameter. Inject level into parameter.
        //              		
		Param = QUIC_PARAM_GENERATOR(Level, Param);
	}
	

    if (((Handle == NULL) ^ (Level == QUIC_PARAM_LEVEL_GLOBAL)) ||
        BufferLength == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_STATUS Status;

    QuicTraceLogVerbose("ApiEnter: [api] Enter %u (%p).",
        QUIC_TRACE_API_GET_PARAM,
        Handle);

    if (Level == QUIC_PARAM_LEVEL_GLOBAL) {
        //
        // Global parameters are processed inline.
        //
        Status = QuicLibraryGetGlobalParam(Param, BufferLength, Buffer);
        goto Error;
    }

    if (Handle->Type == QUIC_HANDLE_TYPE_REGISTRATION ||
        Handle->Type == QUIC_HANDLE_TYPE_CONFIGURATION ||
        Handle->Type == QUIC_HANDLE_TYPE_LISTENER) {
        //
        // Registration, Configuration and Listener parameters are processed inline.
        //
        Status = QuicLibraryGetParam(Handle, Level, Param, BufferLength, Buffer);
        goto Error;
    }

    QUIC_CONNECTION* Connection;
    QUIC_EVENT CompletionEvent;

    if (Handle->Type == QUIC_HANDLE_TYPE_STREAM) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = ((QUIC_STREAM*)Handle)->Connection;
    } else if (Handle->Type == QUIC_HANDLE_TYPE_CONNECTION_SERVER ||
        Handle->Type == QUIC_HANDLE_TYPE_CONNECTION_CLIENT) {
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.Freed);

    if (Connection->WorkerThreadID == QuicCurThreadID()) {
        //
        // Execute this blocking API call inline if called on the worker thread.
        //
        BOOLEAN AlreadyInline = Connection->State.InlineApiExecution;
        if (!AlreadyInline) {
            Connection->State.InlineApiExecution = TRUE;
        }		        
        Status = QuicLibraryGetParam(Handle, Level, Param, BufferLength, Buffer);
		if (!AlreadyInline) {
            Connection->State.InlineApiExecution = FALSE;
        }       
        goto Error;
    }

    QUIC_CONN_VERIFY(Connection, !Connection->State.HandleClosed);

    QUIC_OPERATION Oper;
    QuicZeroMemory(&Oper, sizeof(QUIC_OPERATION));
    QUIC_API_CONTEXT ApiCtx;

    Oper.Type = QUIC_OPER_TYPE_API_CALL;
    Oper.FreeAfterProcess = FALSE;
    Oper.API_CALL.Context = &ApiCtx;

    ApiCtx.Type = QUIC_API_TYPE_GET_PARAM;
    QuicEventInitialize(&CompletionEvent, TRUE, FALSE);
    ApiCtx.Completed = &CompletionEvent;
    ApiCtx.Status = &Status;
    ApiCtx.GET_PARAM.Handle = Handle;
    ApiCtx.GET_PARAM.Level = Level;
    ApiCtx.GET_PARAM.Param = Param;
    ApiCtx.GET_PARAM.BufferLength = BufferLength;
    ApiCtx.GET_PARAM.Buffer = Buffer;

    //
    // Queue the operation and wait for it to be processed.
    //
    QuicConnQueueOper(Connection, &Oper);
    QuicTraceLogVerbose("ApiWaitOperation: [api] Waiting on operation");
    QuicEventWaitForever(CompletionEvent);
    QuicEventUninitialize(CompletionEvent);

Error:

    if(QUIC_FAILED(Status)){
    	QuicTraceLogError("ApiExitStatus: [api] Exit %u", Status);
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicDatagramSend(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_reads_(BufferCount) _Pre_defensive_
        const QUIC_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ QUIC_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    )
{
    QUIC_STATUS Status;
    QUIC_CONNECTION* Connection;
    uint64_t TotalLength;
    QUIC_SEND_REQUEST* SendRequest;

    QuicTraceLogVerbose("ApiEnter: [api] Enter %u (%p).",
        QUIC_TRACE_API_DATAGRAM_SEND,
        Handle);

    if (!IS_CONN_HANDLE(Handle) ||
        Buffers == NULL ||
        BufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
    Connection = (QUIC_CONNECTION*)Handle;

    QUIC_TEL_ASSERT(!Connection->State.Freed);

    TotalLength = 0;
    for (uint32_t i = 0; i < BufferCount; ++i) {
        TotalLength += Buffers[i].Length;
    }

    if (TotalLength > UINT16_MAX) {
        QuicTraceLogError(
            "ConnError: [conn][%p] ERROR, %s.",
            Connection,
            "Send request total length exceeds max");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (...).")
    SendRequest = QuicPoolAlloc(&Connection->Worker->SendRequestPool);
    if (SendRequest == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    SendRequest->Next = NULL;
    SendRequest->Buffers = Buffers;
    SendRequest->BufferCount = BufferCount;
    SendRequest->Flags = Flags;
    SendRequest->TotalLength = TotalLength;
    SendRequest->ClientContext = ClientSendContext;

    Status = QuicDatagramQueueSend(&Connection->Datagram, SendRequest);

Error:
    if (QUIC_FAILED(Status)){
    	QuicTraceLogError("ApiExitStatus: [api] Exit %u",Status);
    }
    return Status;
}

BOOLEAN Get_ChannelState(_In_ _Pre_defensive_ CHANNEL_DATA* Channel)
{
    if (Channel->Connect == NULL)
    {
        return FALSE;
    }
    else
    {
        if (Channel->Mode == CLIENT)
        {
            QUIC_CONNECTION* Connect = (QUIC_CONNECTION*)(Channel->Connect);
            if ((Connect == NULL) || (Connect->Paths == NULL) || (Connect->Paths[0].Binding == NULL))
            {
                return FALSE;
            }
        }
        else
        {
            QUIC_LISTENER* Listener = (QUIC_LISTENER*)(Channel->Connect);
            if ((Listener == NULL) || (Listener->Binding == NULL))
            {
                return FALSE;
            }
        }
    }
	return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_SetSocketOpt(_In_ _Pre_defensive_ CHANNEL_DATA* Channel, _In_ int Level,
                 _In_ int Optname, _In_  void *Optval, _In_ socklen_t Optlen)
{
	uint32_t Count = 0;
	QUIC_SOCKET* Socket = NULL;
		
	BOOLEAN State = Get_ChannelState(Channel);
	if (!State)
	{
		Channel->Attribute = QUIC_ALLOC_NONPAGED(sizeof(Fd_Attribute));
		if (Channel->Attribute == NULL)
		{
			return -1;
		}		
		Channel->Attribute->level = Level;
        Channel->Attribute->optname = Optname;
        Channel->Attribute->optval = Optval;
        Channel->Attribute->optlen = Optlen;
		Channel->Attribute->request = SET_ATTRIBUTE;
	}
	else 
	{
		if (Channel->Mode == CLIENT)
		{
			QUIC_CONNECTION* Connect = (QUIC_CONNECTION*)(Channel->Connect);
			QUIC_SOCKET* Socket = Connect->Paths[0].Binding->Socket;
			Count = Get_SockCount(MsQuicLib.Datapath, CLIENT);
		}
		else 
		{
			QUIC_LISTENER* Listener = (QUIC_LISTENER*)(Channel->Connect);
			Socket = Listener->Binding->Socket;
			Count = Get_SockCount(MsQuicLib.Datapath, SERVER); 
		}		
		SetsockOpt(Socket, Count, Level, Optname, Optval, Optlen);
	}
	return 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuic_GetSocketOpt(_In_ _Pre_defensive_ CHANNEL_DATA* Channel, _In_ int Level,
                _In_ int Optname, _Inout_  void *Optval,  _Inout_ socklen_t *Optlen)
{
    QUIC_SOCKET* Socket = NULL;

    BOOLEAN State = Get_ChannelState(Channel);
    if (!State)
    {
        if (Channel->Attribute != NULL)
        {
			if ((Channel->Attribute->level == Level) && (Channel->Attribute->optname == Optname))
			{
				Optval = Channel->Attribute->optval;
				Optlen = &Channel->Attribute->optlen;	
			}
			return;
		}		
		Optval = NULL;
		*Optlen = 0;
    }
    else
    {
        if (Channel->Mode == CLIENT)
        {
            QUIC_CONNECTION* Connect = (QUIC_CONNECTION*)(Channel->Connect);
            QUIC_SOCKET* Socket = Connect->Paths[0].Binding->Socket;
        }
        else
        {
            QUIC_LISTENER* Listener = (QUIC_LISTENER*)(Channel->Connect);
            Socket = Listener->Binding->Socket;
        }
        GetsockOpt(Socket, 1, Level, Optname, Optval, Optlen);
    }
	return;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
uint64_t
QUIC_API
MsQuic_Recv(_In_ CHANNEL_DATA* Channel, _Inout_ uint8_t* Dest, _Outptr_ uint64_t Len, _In_ int *Flags)
{
    uint64_t Length = 0, Offset = 0;
	do {
		if(!__sync_fetch_and_sub(&Channel->RecvList.Count, 0))
    	{
        	QuicEventWaitForever(Channel->RecvList.REvent);	
    	}

        QuicDispatchLockAcquire(&Channel->RecvList.Lock);
		if (QuicListIsEmpty(&Channel->RecvList.Data))
		{
			QuicDispatchLockRelease(&Channel->RecvList.Lock);
			Length = 0;
			goto End;
		}

        Recv_Buffer* Buffer = QUIC_CONTAINING_RECORD(QuicListRemoveHead(&Channel->RecvList.Data), Recv_Buffer, Node);
        if (Buffer->FreeAddr != NULL)
        {
			QuicRecvDataReturn(Buffer->FreeAddr);
			QuicDispatchLockRelease(&Channel->RecvList.Lock);
            continue;
        }

        if (Buffer->Length > Len)
        {
            memcpy(&Dest[Offset], Buffer->Data, Len);
            Length += Len;
            Buffer->Data += Len;
            Buffer->Length -= Len;
            QuicListInsertHead(&Channel->RecvList.Data, &Buffer->Node);
            QuicDispatchLockRelease(&Channel->RecvList.Lock);
            goto End;
        }
        else
        {
            memcpy(&Dest[Offset], Buffer->Data, Buffer->Length);
            Length += Buffer->Length;
            Buffer->Node.Flink = NULL;
            Offset += Buffer->Length;
			if (Buffer->Finish) {
				 __sync_sub_and_fetch(&Channel->RecvList.Count, 1);
			}
            if (Buffer->Length == Len)
            {
            	QuicFree(Buffer);
				QuicDispatchLockRelease(&Channel->RecvList.Lock);
               	goto End;
            }

            Len -= Buffer->Length;
            QuicFree(Buffer);
        }
		QuicDispatchLockRelease(&Channel->RecvList.Lock);

	}while (__sync_fetch_and_sub(&Channel->RecvList.Count, 0));

End:
    return Length;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CHANNEL_DATA*
QUIC_API
MsQuic_Epoll_Create(_In_ QUIC_SOCKFD *Context)
{
	CHANNEL_DATA* Channel = QuicAlloc(sizeof(CHANNEL_DATA));
	if (Channel == NULL)
	{
		return NULL;
	}
	QuicZeroMemory(Channel, sizeof(CHANNEL_DATA));
	Channel->Context = Context;
    QuicListInitializeHead(&Channel->RecvList.Data);
	QuicEventInitialize(&Channel->RecvList.REvent, FALSE, FALSE);
	QuicDispatchLockInitialize(&Channel->RecvList.Lock);
	Context->NtyChannel = Channel;
    return Channel;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_Epoll_Ctl(_In_ CHANNEL_DATA* EpChannel, _In_ int Op, _Inout_ CHANNEL_DATA* Channel, _Inout_ struct epoll_event *Event)
{
		
	QUIC_SOCKFD* Context = EpChannel->Context;
	if (Op == YMSQUIC_EPOLL_CTL_ADD)
	{
    	Notify_Mes* Buffer = QuicAlloc(sizeof(Notify_Mes));
    	if (Buffer == NULL)
   		{
        	return -1;
    	}
		QuicZeroMemory(Buffer, sizeof(Notify_Mes));			
		Channel->EventType = Event->events;
		Buffer->Channel = Channel;
		QuicDispatchLockAcquire(&EpChannel->RecvList.Lock);
		QuicListInsertHead(&EpChannel->RecvList.Data, &Buffer->Node); 
		QuicDispatchLockRelease(&EpChannel->RecvList.Lock);
		__sync_add_and_fetch(&EpChannel->RecvList.Count, 1); 
	}
	else if (Op == YMSQUIC_EPOLL_CTL_DEL)
	{
		QuicDispatchLockAcquire(&EpChannel->RecvList.Lock);
		if (!__sync_add_and_fetch(&EpChannel->RecvList.Count, 0))
		{
			QuicDispatchLockRelease(&EpChannel->RecvList.Lock);		
			return 0;
		}
		
		for (QUIC_LIST_ENTRY* Entry = EpChannel->RecvList.Data.Flink; Entry != &EpChannel->RecvList.Data; Entry = Entry->Flink)
		{
			Notify_Mes* Buffer = QUIC_CONTAINING_RECORD(Entry, Notify_Mes, Node);
			if (Buffer->Channel == Channel)
			{
				QuicListEntryRemove(Entry);
				 __sync_sub_and_fetch(&EpChannel->RecvList.Count, 1);
				QuicDispatchLockRelease(&EpChannel->RecvList.Lock);
				QuicFree(Buffer);					
				return 0;			
			}	
		}
		QuicDispatchLockRelease(&EpChannel->RecvList.Lock);	
	}
	return 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_GetPeerName(_In_ CHANNEL_DATA* Channel, _Inout_ struct sockaddr* PeerAddr, _In_ socklen_t* addrlen)
{
    QUIC_ADDR Addr;
    QUIC_ADDR_STR IpStr;
	
    QUIC_SOCKFD* Context = Channel->Context;
	struct sockaddr_in* SockAddr = (struct sockaddr_in*)PeerAddr;
    uint32_t AddrLen = sizeof(Addr);

    QUIC_STATUS Status =
        Context->MsQuic->GetParam(
            Channel->Connect,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_REMOTE_ADDRESS,
            &AddrLen,
            &Addr);
    if (QUIC_SUCCEEDED(Status)) {
		QuicAddrToString(&Addr, &IpStr);
		SockAddr->sin_port = htons(QuicAddrGetPort(&Addr));
		SockAddr->sin_addr.s_addr = inet_addr(IpStr.Address);
		return 0;
    }
	return -1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_GetSockName(_In_ CHANNEL_DATA* Channel, _Inout_ struct sockaddr* LocalAddr, _In_ socklen_t* addrlen)
{
    QUIC_ADDR Addr;
    QUIC_ADDR_STR IpStr;

    QUIC_SOCKFD* Context = Channel->Context;
    struct sockaddr_in* SockAddr = (struct sockaddr_in*)LocalAddr;
    uint32_t AddrLen = sizeof(Addr);

    QUIC_STATUS Status =
        Context->MsQuic->GetParam(
            Channel->Connect,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            &AddrLen,
            &Addr);

    if (QUIC_SUCCEEDED(Status)) {
        QuicAddrToString(&Addr, &IpStr);
        SockAddr->sin_port = htons(QuicAddrGetPort(&Addr));
        SockAddr->sin_addr.s_addr = inet_addr(IpStr.Address);
        return 0;
    }
    return -1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
uint32_t
QUIC_API
MsQuic_Epoll_Wait(_In_ CHANNEL_DATA* EpChannel, _Inout_ struct epoll_event * Events, _In_ int Maxevents, _In_ int TimeOut)
{
    int Num = 0;
    QUIC_SOCKFD* Context = EpChannel->Context;

	QuicEventWaitForever(EpChannel->RecvList.REvent);  

    QuicDispatchLockAcquire(&EpChannel->RecvList.Lock);
    for (QUIC_LIST_ENTRY* Entry = EpChannel->RecvList.Data.Flink; Entry != &EpChannel->RecvList.Data; Entry = Entry->Flink)
    {		
        Notify_Mes *Buffer = QUIC_CONTAINING_RECORD(Entry, Notify_Mes, Node);	
		QuicDispatchLockAcquire(&Buffer->Channel->RecvList.Lock);
		if (Buffer->Channel->RecvList.Count > 0)
		{
			Events[Num].data.ptr = Buffer;
            Num++;
		}
		QuicDispatchLockRelease(&Buffer->Channel->RecvList.Lock);
    }
    QuicDispatchLockRelease(&EpChannel->RecvList.Lock);
    return Num;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void*
QUIC_API
MsQuic_Socket(_In_ int Af, _In_ int Type, _In_ int Protocol, _In_ QUIC_SOCKFD* Context)
{
    if ((Af == AF_INET) || (Af == PF_INET))
    {
        QuicAddrSetFamily(&Context->Addr, QUIC_ADDRESS_FAMILY_INET);
    }
    else if (Af == AF_UNSPEC)
    {
        QuicAddrSetFamily(&Context->Addr, QUIC_ADDRESS_FAMILY_UNSPEC);
    }
    else
    {
        QuicAddrSetFamily(&Context->Addr, QUIC_ADDRESS_FAMILY_INET6);
    }

    QuicZeroMemory(&Context->MChannel, sizeof(CHANNEL_DATA));
	Context->MChannel.RecvList.Count = 0;
	Context->MChannel.Context = Context;
	Context->MChannel.ChannelID = 0;
	Context->MChannel.ConnState = QUIC_ONLINE;
    QuicListInitializeHead(&Context->MChannel.RecvList.Data);
    QuicEventInitialize(&Context->MChannel.RecvList.REvent, FALSE, FALSE);
    QuicEventInitialize(&Context->MChannel.RecvList.WEvent, FALSE, FALSE);
	return &Context->MChannel;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_Bind(_In_ CHANNEL_DATA* Channel, _In_ const char* DestAddr, _In_ uint32_t Port)
{
	QUIC_SOCKFD* Context = Channel->Context;
    Context->Addr.Ipv4.sin_family = AF_INET;
    Context->Addr.Ipv4.sin_port = htons(Port);
    Context->Addr.Ipv4.sin_addr.s_addr = inet_addr(DestAddr);
	return 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS 
QUIC_API
MsQuic_Parm_Init(_In_ int Mode, _In_ CHANNEL_DATA* Channel)
{
    QUIC_STATUS Status;    
    const QUIC_REGISTRATION_CONFIG RegConfig = {"udp", QUIC_EXECUTION_PROFILE_LOW_LATENCY};	
	QUIC_SOCKFD* Context = Channel->Context; 

    Context->Alpn[0].Length = sizeof("chan1") -1;
    Context->Alpn[0].Buffer = (uint8_t*)"chan1";

	Context->Alpn[1].Length = sizeof("chan2") - 1;
	Context->Alpn[1].Buffer = (uint8_t*)"chan2";

	Context->Alpn[2].Length = sizeof("chan2") - 1;
	Context->Alpn[2].Buffer = (uint8_t*)"chan2";

	Context->Alpn[3].Length = sizeof("chan3") - 1;
	Context->Alpn[3].Buffer = (uint8_t*)"chan3";

	Context->Alpn[4].Length = sizeof("chan4") - 1;
	Context->Alpn[4].Buffer = (uint8_t*)"chan4";

	Context->Alpn[5].Length = sizeof("chan5") - 1;
	Context->Alpn[5].Buffer = (uint8_t*)"chan5";

	QUIC_SETTINGS Settings;
	QuicZeroMemory(&Settings, sizeof(QUIC_SETTINGS));

	QUIC_CREDENTIAL_CONFIG Config;
	QuicZeroMemory(&Config, sizeof(Config));

    if (Mode == CLIENT)
    {
        Settings.PeerUnidiStreamCount = 1;
        Settings.IsSet.PeerUnidiStreamCount = TRUE;
        Settings.IdleTimeoutMs = 0; 
        Settings.IsSet.IdleTimeoutMs = TRUE;
		Channel->ChannelID = 0;
		Channel->Mode = CLIENT;	
		Config.Type = QUIC_CREDENTIAL_TYPE_NONE;
    	Config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;		
	}
	else
	{
        Settings.PeerUnidiStreamCount = 1;
        Settings.IsSet.PeerUnidiStreamCount = TRUE;
        Settings.IsSet.ServerResumptionLevel = TRUE;
       	Settings.IdleTimeoutMs = 0;  
		Channel->ChannelID = 1024;
		Channel->Mode = SERVER;
        Settings.IsSet.IdleTimeoutMs = TRUE;
		Config.Type = ((QUIC_CREDENTIAL_TYPE)0xF0000000);
	}
	
	if (QUIC_FAILED(Status = Context->MsQuic->RegistrationOpen(&RegConfig, &Context->Registration)))
    {
        QuicTraceLogError("RegistrationOpen failed, 0x%x!\n", Status);
        return Status;
    }
	
 	if (QUIC_FAILED(Status = Context->MsQuic->ConfigurationOpen(Context->Registration, Context->Alpn, ARRAYSIZE(Context->Alpn),
        &Settings, sizeof(Settings), NULL, &Context->Configuration)))
    {
        QuicTraceLogError("Failed to load ConfigurationOpen from args!, 0x%x!\n", Status);
        return Status;
    }

    if (QUIC_FAILED(Status = Context->MsQuic->ConfigurationLoadCredential(Context->Configuration, &Config)))
    {
        QuicTraceLogError("Failed to load configuration from args!, 0x%x!\n", Status);
        return Status;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnFreeResources(_In_ CHANNEL_DATA* Channel)
{
    QUIC_SOCKFD* Context = Channel->Context;
	CHANNEL_DATA* MChannel = &Context->MChannel;
	QUIC_CONNECTION* Connect = (QUIC_CONNECTION*)(Channel->Connect);	

	QuicDispatchLockAcquire(&Channel->RecvList.Lock);
    while (!QuicListIsEmpty(&Channel->RecvList.Data))
    {
        Recv_Buffer* Oper = QUIC_CONTAINING_RECORD(QuicListRemoveHead(&Channel->RecvList.Data), Recv_Buffer, Node);
        Oper->Node.Flink = NULL;
        QuicFree(Oper);
    }
	QuicDispatchLockRelease(&Channel->RecvList.Lock);

   	QuicDispatchLockUninitialize(&Channel->RecvList.Lock);
    QuicEventUninitialize(Channel->RecvList.REvent);
    QuicEventUninitialize(Channel->RecvList.WEvent);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuic_Close(_In_ CHANNEL_DATA* Channel)
{
    QUIC_SOCKFD* Context = Channel->Context;
	CHANNEL_DATA* MChannel = &Context->MChannel;

	if (Channel->Mode == CLIENT)
    {
        Context->MsQuic->ConnectionShutdown(Channel->Connect, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
    } else {
		Context->MsQuic->ListenerClose((&Context->MChannel)->Connect);
		
		if (!QuicListIsEmpty(&Context->MChannel.RecvList.Data))
		{
			for (QUIC_LIST_ENTRY* Entry = Context->MChannel.RecvList.Data.Flink; Entry != &Context->MChannel.RecvList.Data; Entry = Entry->Flink)
			{
				CHANNEL_DATA* Buffer =QUIC_CONTAINING_RECORD(Entry, CHANNEL_DATA, Node);
				if (Buffer == NULL) { break; }
				Context->MsQuic->ConnectionShutdown(Buffer->Connect, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
				Context->MsQuic->StreamClose(Buffer->Connect);
			}
		}
	}
	
	if (Context->Configuration)
    {
    	Context->MsQuic->ConfigurationClose(Context->Configuration);
    }

    if (Context->MsQuic)
    {
    	if (Context->Registration)
        {
        	Context->MsQuic->RegistrationClose(Context->Registration);
        }
        MsQuicClose(Context->MsQuic);
    }
	
	if (Channel->Mode == CLIENT)
	{
		QuicConnFreeResources(Channel);
		return;
	}

	if (Channel->Mode == SERVER) {
    	while (!QuicListIsEmpty(&Context->MChannel.RecvList.Data))
    	{
    		CHANNEL_DATA* Oper = QUIC_CONTAINING_RECORD(QuicListRemoveHead(&Context->MChannel.RecvList.Data), CHANNEL_DATA, Node);
        	QuicConnFreeResources(Oper);
        	Oper->Node.Flink = NULL;
       	 	QuicFree(Oper);
    	}
	}

    if (Context->NtyChannel != NULL)
    {
        while (!QuicListIsEmpty(&Context->NtyChannel->RecvList.Data))
        {
            Notify_Mes* Oper = QUIC_CONTAINING_RECORD(QuicListRemoveHead(&Context->NtyChannel->RecvList.Data), Notify_Mes, Node);
            Oper->Node.Flink = NULL;
            QuicFree(Oper);
        }
        QuicDispatchLockUninitialize(&Context->NtyChannel->RecvList.Lock);
        QuicFree(Context->NtyChannel);
        Context->NtyChannel = NULL;
    }
}


_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
StreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* _Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    QUIC_SOCKFD* Context = (QUIC_SOCKFD*)_Context;
    QUIC_CONNECTION* ConnectID = ((QUIC_STREAM*)Stream)->Connection;
	CHANNEL_DATA *Channel = ConnectID->Channel;
    switch (Event->Type) {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
			QuicEventSet(Channel->RecvList.WEvent);
            break;

        case QUIC_STREAM_EVENT_RECEIVE:
            break;

		case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
	    	break;

        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            break;

        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
            break;

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            Context->MsQuic->StreamClose(Stream);
            break;

        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
ConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* _Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    QUIC_SOCKFD* Context = (QUIC_SOCKFD*)_Context;
	QUIC_CONNECTION* Connect = (QUIC_CONNECTION*)Connection;
	CHANNEL_DATA* Channel = (CHANNEL_DATA*)Connect->Channel;

    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            Context->MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
            break;

		case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
			break;

		case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
			MsQuic_CloseConnect(Channel);			
        	break;

        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            Context->MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)StreamCallback, _Context);
            break;

        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuic_CloseConnect(_In_ CHANNEL_DATA* Channel)
{
	QUIC_SOCKFD* Context = Channel->Context;
	BOOLEAN Flag = FALSE;	

	QuicDispatchLockAcquire(&Context->MChannel.RecvList.Lock)
    if (Channel->Mode == CLIENT)
    {
        if (Channel->ConnState != QUIC_CUTOFF)
        {
            Channel->ConnState = QUIC_CUTOFF;
            Flag = TRUE;
            goto End;
        }
		QuicDispatchLockRelease(&Context->MChannel.RecvList.Lock);
		return;
    }

	if (QuicListIsEmpty(&Context->MChannel.RecvList.Data))
	{
		QuicDispatchLockRelease(&Context->MChannel.RecvList.Lock);
		return;
	}
	
   	for (QUIC_LIST_ENTRY* Entry = Context->MChannel.RecvList.Data.Flink; Entry != &Context->MChannel.RecvList.Data; Entry = Entry->Flink)
	{
		CHANNEL_DATA* Buffer = QUIC_CONTAINING_RECORD(Entry, CHANNEL_DATA, Node);
		if (Buffer && (Buffer->ConnState != QUIC_CUTOFF) && (Channel->Connect == Buffer->Connect))
		{
			Buffer->ConnState = QUIC_CUTOFF;
			Flag = TRUE;
			break;
		}
	}
End:
	QuicDispatchLockRelease(&Context->MChannel.RecvList.Lock);
	if (Flag)
	{
        Context->MsQuic->ConnectionClose(Channel->Connect);
	}
	return;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_Send(_In_ CHANNEL_DATA* Channel, _Inout_ void* Buffer)
{
    HQUIC Stream;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)Buffer;
    QUIC_SEND_FLAGS Send_Flag = QUIC_SEND_FLAG_NONE;
    QUIC_SOCKFD* Context  = Channel->Context;
   
    if (Channel->Mode == CLIENT)
    {
	if (Channel->ChannelID == 0)
	{
	    SendBuffer = QUIC_ALLOC_PAGED(sizeof(QUIC_BUFFER) + sizeof(char)*32);
	    if (SendBuffer == NULL)
	    {
	         Status = QUIC_STATUS_OUT_OF_MEMORY;
	         goto End;
	    }		
	    SendBuffer->Buffer = (uint8_t*)SendBuffer + sizeof(QUIC_BUFFER);
    	    snprintf((char*)SendBuffer->Buffer, sizeof(char)*32, "%s%u", GET_CHANNELID, Channel->ChannelID);
    	    SendBuffer->Length = strlen((char*)SendBuffer->Buffer);
	} 
    } else {
        if (!strncmp(GET_CHANNELID, (char*)SendBuffer->Buffer, strlen(GET_CHANNELID)))
        {
	    uint32_t ID = __sync_fetch_and_add(&Context->MChannel.ChannelID, 1);
            SendBuffer = QUIC_ALLOC_PAGED(sizeof(QUIC_BUFFER) + sizeof(char)*32);
            if (SendBuffer == NULL)
            {
                Status = QUIC_STATUS_OUT_OF_MEMORY;
		goto End;
            }	
	    SendBuffer->Buffer = (uint8_t*)SendBuffer + sizeof(QUIC_BUFFER);	
	    snprintf((char*)SendBuffer->Buffer, sizeof(char)*32, "%s%u\r\n",GET_CHANNELID, ID);
	    SendBuffer->Length = strlen((char*)SendBuffer->Buffer);	
        } 	
   }

    uint32_t Length = SendBuffer->Length;
    if (QUIC_FAILED(Status = Context->MsQuic->StreamOpen(Channel->Connect, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, StreamCallback, Context, &Stream)))
    {
		QuicTraceLogError("StreamOpen failed, 0x%x!\n", Status);
        goto End;
    }

    if (QUIC_FAILED(Status = Context->MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_ASYNC)))
    {
        QuicTraceLogError("StreamStart failed, 0x%x!\n", Status);
		Context->MsQuic->StreamClose(Stream);
        goto End;
  	}

   do {
        if (Length > IO_SIZE)
        {
            SendBuffer->Length = IO_SIZE;
            Send_Flag = QUIC_SEND_FLAG_NONE;
            Length -= IO_SIZE;
        }
        else
        {
            SendBuffer->Length = Length;
           	Send_Flag = QUIC_SEND_FLAG_FIN;	
        }
	
        if (QUIC_FAILED(Status = Context->MsQuic->StreamSend(Stream, SendBuffer, 1, Send_Flag, NULL)))
        {
            QuicTraceLogError("StreamSend failed, 0x%x!\n", Status);
			Context->MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
			goto End;
        }

		QuicEventWaitForever(Channel->RecvList.WEvent);	
        if (Send_Flag == QUIC_SEND_FLAG_NONE)
        {
            SendBuffer->Buffer = SendBuffer->Buffer + IO_SIZE;
        }
		
    } while (Send_Flag != QUIC_SEND_FLAG_FIN);	

	return QUIC_STATUS_SUCCESS;

End:

	MsQuic_CloseConnect(Channel);
	return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_GetChanID(_In_ CHANNEL_DATA* Channel)
{
	QUIC_CONNECTION* Connect = (QUIC_CONNECTION*)(Channel->Connect);
    char Data[128] = {0};
	int State = 0;
	QUIC_BUFFER* SendBuffer = NULL;
	uint64_t Length = 0;

    Connect->Channel = Channel;
  	if (QUIC_FAILED(MsQuic_Send(Channel, SendBuffer)))
    {
        QuicTraceLogError("Client Send failed\n");
       	return QUIC_STATUS_INVALID_STATE;
    }
	QuicZeroMemory(Data, sizeof(Data));	

	do {
		Length = MsQuic_Recv(Channel, (void*)Data, sizeof(Data), &State);
   	 	if (!Length && State)
    	{
        	return QUIC_STATUS_CONNECTION_REFUSED;
    	}
	} while (!Length);

    if (_strnicmp(Data, "GET_CHANNELID", strlen("GET_CHANNELID")))
    {
		return QUIC_STATUS_INVALID_STATE;
	}

   	char* Begin = Data + 13;
    char* End = strstr(Begin, "\r\n");
    if (End == NULL)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    *End = '\0';
    Channel->ChannelID = atoi(Begin);
	return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_CSInit(_In_ QUIC_SOCKFD* Context, _In_ HQUIC ConnectID, _In_ int Mode)
{
    QUIC_CONNECTION* Connect = (QUIC_CONNECTION*)ConnectID;

	CHANNEL_DATA* Channel = (CHANNEL_DATA*)QuicAlloc(sizeof(CHANNEL_DATA));
    if (Channel == NULL)
    {
		return QUIC_STATUS_OUT_OF_MEMORY;
	}
	
	QuicZeroMemory(Channel, sizeof(CHANNEL_DATA));
	QuicListInitializeHead(&Channel->RecvList.Data); 
    QuicEventInitialize(&Channel->RecvList.REvent, FALSE, FALSE);
    QuicEventInitialize(&Channel->RecvList.WEvent, FALSE, FALSE);
    QuicDispatchLockInitialize(&Channel->RecvList.Lock);

    Connect->Channel = Channel;
	Channel->Connect = ConnectID;
	Channel->Context = Context;
	Channel->Mode = Mode;

	QuicDispatchLockAcquire(&Context->MChannel.RecvList.Lock);
	if (Context->MChannel.RecvList.Count >= Context->MChannel.Count)
	{
		Channel->ConnState = QUIC_WAITLISTEN;
        QuicListInsertTail(&Context->MChannel.RecvList.Data, &Channel->Node);
	}
	else	
	{	
		Context->MChannel.RecvList.Count++;
		Channel->ConnState = QUIC_ONLINE;
		QuicListInsertHead(&Context->MChannel.RecvList.Data, &Channel->Node);
	}
	QuicDispatchLockRelease(&Context->MChannel.RecvList.Lock);

	if (Context->MChannel.EventType == YMSQUIC_EPOLLIN)
	{
		QuicEventSet(Context->NtyChannel->RecvList.REvent);
	}

   	return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_Connect(_In_ CHANNEL_DATA* Channel, _In_ const char* DstIp, _In_ uint32_t UdpPort) 
{
	QUIC_SOCKFD* Context = Channel->Context;
	QUIC_STATUS Status = QUIC_STATUS_SUCCESS;	
	QUIC_CONNECTION* Conn = NULL;

	if (QUIC_FAILED(Status = MsQuic_Parm_Init(CLIENT, Channel)))
    {
        QuicTraceLogError("Client parameter init failed, 0x%x!\n", Status);
        goto End;
    }

   	if (QUIC_FAILED(Status = Context->MsQuic->ConnectionOpen(Context->Registration, ConnectionCallback, Context, &Channel->Connect)))
    {
        QuicTraceLogError("ConnectionOpen failed, 0x%x!\n", Status);
        goto End;
    }

	((QUIC_CONNECTION*)(Channel->Connect))->Attribute = Context->MChannel.Attribute;
    if (QUIC_FAILED(Status = Context->MsQuic->ConnectionStart(Channel->Connect, Context->Configuration, QUIC_ADDRESS_FAMILY_UNSPEC,
		 DstIp,  UdpPort)))
    {
        QuicTraceLogError("ConnectionStart failed, 0x%x!\n", Status);
        goto End;
    }
	
	if (QUIC_FAILED(Status = MsQuic_GetChanID(Channel)))
    {
        QuicTraceLogError("Client get channel number failed, 0x%x!\n", Status);
		goto End;
    }
	return QUIC_STATUS_SUCCESS;
		
End:
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
listenerCallback(
    _In_ HQUIC listener,
    _In_opt_ void* _Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    QUIC_SOCKFD* Context = (QUIC_SOCKFD*)_Context;

    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION)
    {
		if (QUIC_FAILED(MsQuic_CSInit(Context, Event->NEW_CONNECTION.Connection, SERVER)))
        {
            QuicTraceLogError("Initialization of the connected cleint failed, 0x%x!\n", Status);
            return Status;
        }
	
        Context->MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ConnectionCallback, (void*)Context);
        Status = Context->MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Context->Configuration);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_Listen(_In_ CHANNEL_DATA* Channel, int Backlog)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
	QUIC_SOCKFD* Context = Channel->Context;

    if (QUIC_FAILED(Status = MsQuic_Parm_Init(SERVER, Channel)))
    {
        QuicTraceLogError("Server parmeter init failed, 0x%x!\n", Status);
        goto End;
    }

    if (QUIC_FAILED(Status = Context->MsQuic->ListenerOpen(Context->Registration, listenerCallback, (void*)Context, &Channel->Connect)))
    {
        QuicTraceLogError("listenerOpen failed, 0x%x!\n", Status);
        goto End;
    }
	
    ((QUIC_LISTENER*)(Channel->Connect))->Attribute = Channel->Attribute;
    if (QUIC_FAILED(Status = Context->MsQuic->ListenerStart(Channel->Connect, Context->Alpn, ARRAYSIZE(Context->Alpn), &Context->Addr)))
    {
        QuicTraceLogError("listenerStart failed, 0x%x!\n", Status);
        goto End;
    }
	
	Channel->Count = Backlog;
    return Status;

End:
	return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void*
QUIC_API
MsQuic_Accept(_In_ CHANNEL_DATA* Channel)
{
	CHANNEL_DATA* Buffer = NULL;
	CHANNEL_DATA* Tmp = NULL;
	CHANNEL_DATA* MChannel = &Channel->Context->MChannel;

	QuicDispatchLockAcquire(&MChannel->RecvList.Lock);
	if (MChannel->RecvList.Count <= 0)
	{
		goto End;
	}		

	MChannel->RecvList.Count--;
    for (QUIC_LIST_ENTRY* Entry = MChannel->RecvList.Data.Flink; Entry != &MChannel->RecvList.Data; Entry = Entry->Flink)
	{
       	Buffer = QUIC_CONTAINING_RECORD(Entry, CHANNEL_DATA, Node);
		if (Buffer == NULL)
		{
			goto End;
		}
		if ((Buffer->ConnState == QUIC_ONLINE) && (Tmp == NULL))
		{
			Buffer->ConnState = QUIC_ACCEPT;
			Buffer->RecvList.Count = 0;
			Tmp = Buffer;
		}
		if (Buffer->ConnState == QUIC_WAITLISTEN)
		{
			Buffer->ConnState = QUIC_ONLINE;
			MChannel->RecvList.Count++;
			break;
		} 	
	}

End:
	QuicDispatchLockRelease(&MChannel->RecvList.Lock);
	return Tmp;	
}
