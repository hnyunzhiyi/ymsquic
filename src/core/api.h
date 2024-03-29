/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicRegistrationOpen(
    _In_opt_ const QUIC_REGISTRATION_CONFIG* Config,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
    HQUIC* Registration
);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicRegistrationClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
    HQUIC Handle
);

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicRegistrationShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConfigurationOpen(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
    const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_reads_bytes_opt_(SettingsSize)
    const QUIC_SETTINGS* Settings,
    _In_ uint32_t SettingsSize,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Configuration, __drv_allocatesMem(Mem)) _Pre_defensive_
    HQUIC* Configuration
);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicConfigurationClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
    HQUIC Handle
);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConfigurationLoadCredential(
    _In_ _Pre_defensive_ HQUIC Configuration,
    _In_ _Pre_defensive_ const QUIC_CREDENTIAL_CONFIG* CredConfig
);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicListenerOpen(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ _Pre_defensive_ QUIC_LISTENER_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Listener, __drv_allocatesMem(Mem)) _Pre_defensive_
    HQUIC *Listener
);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicListenerClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
    HQUIC Handle
);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicListenerStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
    const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ const QUIC_ADDR* LocalAddress
);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicListenerStop(
    _In_ _Pre_defensive_ HQUIC Handle
);

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionOpen(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ _Pre_defensive_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Connection, __drv_allocatesMem(Mem)) _Pre_defensive_
    HQUIC *Connection
);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicConnectionClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
    HQUIC Handle
);

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicConnectionShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
);

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ HQUIC ConfigHandle,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_opt_z_(QUIC_MAX_SNI_LENGTH)
    const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
);

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionSetConfiguration(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ HQUIC ConfigHandle
);

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConnectionSendResumptionTicket(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_SEND_RESUMPTION_FLAGS Flags,
    _In_ uint16_t DataLength,
    _In_reads_bytes_opt_(DataLength)
    const uint8_t* ResumptionData
);

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamOpen(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_STREAM_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Stream, __drv_allocatesMem(Mem)) _Pre_defensive_
    HQUIC *Stream
);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuic_CloseConnect(_In_ CHANNEL_DATA* Channel);


_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicStreamClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
    HQUIC Handle
);

_When_(Flags & QUIC_STREAM_START_FLAG_ASYNC, _IRQL_requires_max_(DISPATCH_LEVEL))
_When_(!(Flags & QUIC_STREAM_START_FLAG_ASYNC), _IRQL_requires_max_(PASSIVE_LEVEL))
QUIC_STATUS
QUIC_API
MsQuicStreamStart(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_START_FLAGS Flags
);

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamShutdown(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode
);

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
);

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamReceiveComplete(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ uint64_t BufferLength
);

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicStreamReceiveSetEnabled(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ BOOLEAN IsEnabled
);

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
);

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
);

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
);

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_SetSocketOpt(_In_ _Pre_defensive_ CHANNEL_DATA* Channel,
                    _In_ int Level,
                    _In_ int Optname,
                    _In_ void *Optval,
                    _In_ socklen_t Optlen);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuic_GetSocketOpt(_In_ _Pre_defensive_ CHANNEL_DATA* Channel,
                    _In_ int Level,
                    _In_ int Optname,
                    _Inout_ void *Optval,
                    _Inout_ socklen_t *Optlen);

_IRQL_requires_max_(PASSIVE_LEVEL)
CHANNEL_DATA*
QUIC_API
MsQuic_Epoll_Create(_In_ QUIC_SOCKFD* _Context);

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_Epoll_Ctl(_In_ CHANNEL_DATA* EpChannel,
                 _In_ int Op,
                 _Inout_ CHANNEL_DATA* Channel,
                 _Inout_ struct epoll_event *Event);


_IRQL_requires_max_(PASSIVE_LEVEL)
uint32_t
QUIC_API
MsQuic_Epoll_Wait(_In_ CHANNEL_DATA* Channel,
                  _Inout_ struct epoll_event * Events,
                  _In_ int Maxevents,
                  _In_ int TimeOut);

_IRQL_requires_max_(PASSIVE_LEVEL)
void*
QUIC_API
MsQuic_Socket(_In_ int Af,
              _In_ int Type,
              _In_ int Protocol,
              _In_ QUIC_SOCKFD* Context);

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_Bind(_In_ CHANNEL_DATA* Channel,
            _In_ const struct sockaddr *addr,
            _In_ socklen_t addrlen);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
QuicRemoteGetPort(_In_ const QUIC_API_TABLE* Msquic,
                  _In_ HQUIC Handle);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_Parm_Init(_In_ int Mode,
                 _In_ CHANNEL_DATA* Channel);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuic_Close(_In_ CHANNEL_DATA* Channel);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
StreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* _Context,
    _Inout_ QUIC_STREAM_EVENT* Event);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
ConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* _Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_Connect(_In_ CHANNEL_DATA* Channel,
               _In_ const struct sockaddr *addr,
               _In_ socklen_t addrlen);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_Send(_In_ CHANNEL_DATA* Channel,
            _Inout_ void *Buffer);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
YmsQuic_SocketIsClose(_In_ void* _Channel);

_IRQL_requires_max_(PASSIVE_LEVEL)
uint64_t
QUIC_API
MsQuic_Recv(_In_ CHANNEL_DATA* Channel,
            _Inout_ uint8_t* Dest,
            _In_ uint64_t Len,
            _In_ int *Flags);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_GetChanID(_In_ CHANNEL_DATA* Channel);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_CSInit(_In_ QUIC_SOCKFD *Context,
              _In_ HQUIC ConnectID, int Mode);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
listenerCallback(
    _In_ HQUIC listener,
    _In_opt_ void* _Context,
    _Inout_ QUIC_LISTENER_EVENT* Event);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuic_Listen(_In_ CHANNEL_DATA* Channel, _In_ int Backlog);

_IRQL_requires_max_(PASSIVE_LEVEL)
void*
QUIC_API
MsQuic_Accept(_In_ CHANNEL_DATA* Channel);

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_GetPeerName(_In_ CHANNEL_DATA* Channel,
                   _Inout_ struct sockaddr* PeerAddr,
                   _In_ socklen_t* addrlen);

_IRQL_requires_max_(PASSIVE_LEVEL)
int
QUIC_API
MsQuic_GetSockName(_In_ CHANNEL_DATA* Channel,
                   _Inout_ struct sockaddr* LocalAddr,
                   _In_ socklen_t* addrlen);

