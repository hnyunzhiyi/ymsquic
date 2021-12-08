/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux

--*/

#if 1
#define _GNU_SOURCE
#include "platform_internal.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/in6.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "quic_platform_dispatch.h"
#endif 

QUIC_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Length) <= sizeof(size_t)), "(sizeof(QUIC_BUFFER.Length) == sizeof(size_t) must be TRUE.");
QUIC_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Buffer) == sizeof(void*)), "(sizeof(QUIC_BUFFER.Buffer) == sizeof(void*) must be TRUE.");

#ifdef HAS_SENDMMSG
#define QUIC_SENDMMSG sendmmsg
#else

static int cxplat_sendmmsg_shim(int fd, struct mmsghdr* Messages, unsigned int MessageLen, int Flags)
{
    unsigned int SuccessCount = 0;
    while (SuccessCount < MessageLen) {
        int Result = sendmsg(fd, &Messages[SuccessCount].msg_hdr, Flags);
        if (Result < 0) {
            return SuccessCount == 0 ? Result : (int)SuccessCount;
        }
        Messages[SuccessCount].msg_len = Result;
        SuccessCount++;
    }
    return SuccessCount;
}
#define QUIC_SENDMMSG cxplat_sendmmsg_shim
#endif

//
// The maximum single buffer size for sending coalesced payloads.
//
#define QUIC_LARGE_SEND_BUFFER_SIZE         0xFFFF

#ifdef DISABLE_POSIX_GSO
#ifdef UDP_SEGMENT
#undef UDP_SEGMENT
#endif
#endif

//
// If we have UDP segmentation support, use a single batch. Without UDP
// segmentation, increase batch size to gain back some performance
//
#ifdef UDP_SEGMENT
#define QUIC_MAX_BATCH_SEND 1
#else
#define QUIC_MAX_BATCH_SEND 43
#endif
#define QUIC_MAX_BATCH_RECEIVE 43

//
// A receive block to receive a UDP packet over the sockets.
//
typedef struct QUIC_DATAPATH_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //
    QUIC_POOL* OwningPool;

    //
    // The recv buffer used by MsQuic.
    //
    QUIC_RECV_DATA RecvPacket;

    //
    // Represents the address (source and destination) information of the
    // packet.
    //
    QUIC_TUPLE Tuple;

    //
    // Buffer that actually stores the UDP payload.
    //
    uint8_t Buffer[MAX_UDP_PAYLOAD_LENGTH];

    //
    // This follows the recv block.
    //
    // QUIC_RECV_PACKET RecvContext;

} QUIC_DATAPATH_RECV_BLOCK;

//
// Send context.
//

typedef struct QUIC_SEND_DATA {
    //
    // Indicates if the send should be bound to a local address.
    //
    BOOLEAN Bind;

    //
    // The local address to bind to.
    //
    QUIC_ADDR LocalAddress;

    //
    // The remote address to send to.
    //
    QUIC_ADDR RemoteAddress;

    //
    // Linkage to pending send list.
    //
    QUIC_LIST_ENTRY PendingSendLinkage;
    
	//
	// The type of ECN markings needed for send.
    //
    QUIC_ECN_TYPE ECN;

    //
    // The proc context owning this send context.
    //
    struct QUIC_DATAPATH_PROC_CONTEXT *Owner;

    //
    //The number of messages of this buffer that have been sent.
    //      
	size_t SentMessagesCount;


    //
    //The send segmentation size; zero if segmentation is not performed.
    //      
	uint16_t SegmentSize;

    //
    // The total buffer size for Buffers.
    //    
   	uint32_t TotalSize;


    //
    // BufferCount - The buffer count in use.
    //
    // CurrentIndex - The current index of the Buffers to be sent.
    //
    // Buffers - Send buffers.
    //
    // Iovs - IO vectors used for doing sends on the socket.
    //
    // TODO: Better way to reconcile layout difference
    // between QUIC_BUFFER and struct iovec?
    //

    size_t BufferCount;
    size_t CurrentIndex;
    QUIC_BUFFER Buffers[QUIC_MAX_BATCH_SEND];
    struct iovec Iovs[QUIC_MAX_BATCH_SEND];

    //
    //The QUIC_BUFFER returned to the client for segmented sends.
    //    
	QUIC_BUFFER ClientBuffer;

} QUIC_SEND_DATA;

typedef struct QUIC_RECV_MSG_CONTROL_BUFFER {
    char Data[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
              CMSG_SPACE(sizeof(struct in_pktinfo)) +
              2 * CMSG_SPACE(sizeof(int))];
} QUIC_RECV_MSG_CONTROL_BUFFER;

typedef struct QUIC_DATAPATH_PROC_CONTEXT QUIC_DATAPATH_PROC_CONTEXT;

//
// Socket context.
//
typedef struct QUIC_SOCKET_CONTEXT {

    //
    // The datapath binding this socket context belongs to.
    //
    QUIC_SOCKET* Binding;

    //
    //The datapath proc context this socket belongs to.
    //       
	QUIC_DATAPATH_PROC_CONTEXT* ProcContext;

    //
    // The socket FD used by this socket context.
    //
    int SocketFd;

    //
    // The cleanup event FD used by this socket context.
    //
    int CleanupFd;

    //
    // Used to register different event FD with epoll.
    //
#define QUIC_SOCK_EVENT_CLEANUP 0
#define QUIC_SOCK_EVENT_SOCKET  1
    uint8_t EventContexts[2];

    //
    //The I/O vector for receive datagrams.
    //        
    struct iovec RecvIov[QUIC_MAX_BATCH_RECEIVE];

    //
    //The control buffer used in RecvMsgHdr.
    //     
    QUIC_RECV_MSG_CONTROL_BUFFER RecvMsgControl[QUIC_MAX_BATCH_RECEIVE];

    //
    //The buffer used to receive msg headers on socket.
    //     
    struct mmsghdr RecvMsgHdr[QUIC_MAX_BATCH_RECEIVE];

    //
    //The receive block currently being used for receives on this socket.
    //      
    QUIC_DATAPATH_RECV_BLOCK* CurrentRecvBlocks[QUIC_MAX_BATCH_RECEIVE];

    //
    //The head of list containg all pending sends on this socket.
    //       
    QUIC_LIST_ENTRY PendingSendDataHead;

    //
    //Lock around the PendingSendData list.
    //       
    QUIC_LOCK PendingSendDataLock;
} QUIC_SOCKET_CONTEXT;


//
// Datapath binding.
//
typedef struct QUIC_SOCKET {

    //
    //Synchronization mechanism for cleanup.
    //Make sure events are in front for cache alignment.
    //  
    QUIC_RUNDOWN_REF Rundown;

    //
    //A pointer to datapath object.
    //   
    QUIC_DATAPATH* Datapath;

    //
    //The client context for this binding.
    //  
    void *ClientContext;

    //
    //The local address for the binding.
    //    
	QUIC_ADDR LocalAddress;

    //
    //The remote address for the binding.
    //    
    QUIC_ADDR RemoteAddress;

    //
    //Indicates the binding connected to a remote IP address.
    //    
	BOOLEAN Connected : 1;

    //
    //Indicates the binding is shut down.
    //      
	BOOLEAN Shutdown : 1;
    
    //
    //Flag indicates the socket has a default remote destination.
    //      
    BOOLEAN HasFixedRemoteAddress : 1;

    //
    //Flag indicates the binding is being used for PCP.
    //      
    BOOLEAN PcpBinding : 1;

    //
    //The MTU for this binding.
    //     
    uint16_t Mtu;

    //
    //Set of socket contexts one per proc.
    //     
	QUIC_SOCKET_CONTEXT SocketContexts[];
} QUIC_SOCKET;

//
// A per processor datapath context.
//
typedef struct QUIC_DATAPATH_PROC_CONTEXT {

    //
    //A pointer to the datapath.
    //      
    QUIC_DATAPATH* Datapath;

    //
    //The Epoll FD for this proc context.
    //        
    int EpollFd;

    //
    //The event FD for this proc context.
    //       
    int EventFd;

    //
    //The index of the context in the datapath's array.
    //       
    uint32_t Index;

    //
    //The epoll wait thread.
    //       
    QUIC_THREAD EpollWaitThread;

    //
    //Pool of receive packet contexts and buffers to be shared by all sockets
    //on this core.
    //           
    QUIC_POOL RecvBlockPool;

    //
    //Pool of send buffers to be shared by all sockets on this core.
    //      
    QUIC_POOL SendBufferPool;

    //
    //Pool of large segmented send buffers to be shared by all sockets on this
    //core.
    //           
    QUIC_POOL LargeSendBufferPool;

    //
    //Pool of send data contexts to be shared by all sockets on this core.
    //       
    QUIC_POOL SendDataPool;

}QUIC_DATAPATH_PROC_CONTEXT;

//
// Represents a datapath object.
//

typedef struct QUIC_DATAPATH {

    //
    //A reference rundown on the datapath binding.
    //Make sure events are in front for cache alignment.
    //         
    QUIC_RUNDOWN_REF BindingsRundown;

    //
    //Set of supported features.
    //       
    uint32_t Features;

    //
    // If datapath is shutting down.
    //
    BOOLEAN volatile Shutdown;

    //
    // The max send batch size.
    // TODO: See how send batching can be enabled.
    //
    uint8_t MaxSendBatchSize;

    //
    // UDP handlers.
    //       
 	QUIC_UDP_DATAPATH_CALLBACKS UdpHandlers;

    //
    //The length of recv context used by MsQuic.
    //       
 	size_t ClientRecvContextLength;

    //
    //The proc count to create per proc datapath state.
    //       
    uint32_t ProcCount;

    //
    // The per proc datapath contexts.
    //
    QUIC_DATAPATH_PROC_CONTEXT ProcContexts[];

} QUIC_DATAPATH;



void*
QuicDataPathWorkerThread(
    _In_ void* Context
    );

QUIC_STATUS
QuicSocketSendInternal(
    _In_ QUIC_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_SEND_DATA* SendData,
    _In_ BOOLEAN IsPendedSend
    );

#ifdef UDP_SEGMENT
QUIC_STATUS
QuicDataPathQuerySockoptSupport(
    _Inout_ QUIC_DATAPATH* Datapath
    )
{
    int Result;
    socklen_t OptionLength;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    int UdpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (UdpSocket == INVALID_SOCKET) {
        int SockError = errno;
        QuicTraceLogWarning(
            "[data] UDP send segmentation helper socket failed to open, 0x%x",
            SockError);
        goto Error;
    }

    int SegmentSize;
    OptionLength = sizeof(SegmentSize);
    Result =
        getsockopt(
            UdpSocket,
            IPPROTO_UDP,
            UDP_SEGMENT,
            &SegmentSize,
            &OptionLength);
    if (Result != 0) {
        int SockError = errno;
        QuicTraceLogWarning(
            "[data] Query for UDP_SEGMENT failed, 0x%x",
            SockError);
    } else {
        Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;
    }

Error:
    if (UdpSocket != INVALID_SOCKET) {
        close(UdpSocket);
    }

    return Status;
}
#endif

void
QuicProcessorContextUninitialize(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    const eventfd_t Value = 1;
    eventfd_write(ProcContext->EventFd, Value);
    QuicThreadWait(&ProcContext->EpollWaitThread);
    QuicThreadDelete(&ProcContext->EpollWaitThread);

    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, ProcContext->EventFd, NULL);
    close(ProcContext->EventFd);
    close(ProcContext->EpollFd);

    QuicPoolUninitialize(&ProcContext->RecvBlockPool);
    QuicPoolUninitialize(&ProcContext->LargeSendBufferPool);
    QuicPoolUninitialize(&ProcContext->SendBufferPool);
    QuicPoolUninitialize(&ProcContext->SendDataPool);
}

QUIC_STATUS
QuicProcessorContextInitialize(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ uint32_t Index,
    _Out_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int EpollFd = INVALID_SOCKET;
    int EventFd = INVALID_SOCKET;
    int Ret = 0;
    uint32_t RecvPacketLength = 0;
    BOOLEAN EventFdAdded = FALSE;
   	BOOLEAN ThreadCreated = FALSE;

    QUIC_DBG_ASSERT(Datapath != NULL);

    RecvPacketLength =
        sizeof(QUIC_DATAPATH_RECV_BLOCK) + Datapath->ClientRecvContextLength;

    ProcContext->Index = Index;
    QuicPoolInitialize(
        TRUE,
        RecvPacketLength,
        QUIC_POOL_DATA,
        &ProcContext->RecvBlockPool);
    QuicPoolInitialize(
        TRUE,
        MAX_UDP_PAYLOAD_LENGTH,
        QUIC_POOL_DATA,
        &ProcContext->SendBufferPool);
    QuicPoolInitialize(
        TRUE,
        QUIC_LARGE_SEND_BUFFER_SIZE,
        QUIC_POOL_DATA,
        &ProcContext->LargeSendBufferPool);
    QuicPoolInitialize(
        TRUE,
        sizeof(QUIC_SEND_DATA),
      	QUIC_POOL_PLATFORM_SENDCTX,
        &ProcContext->SendDataPool);

    EpollFd = epoll_create1(EPOLL_CLOEXEC);
    if (EpollFd == INVALID_SOCKET) {
        Status = errno;
        QuicTraceLogError(
            "LibraryErrorStatus: [lib] ERROR, %u, %s.",
            Status,
            "epoll_create1(EPOLL_CLOEXEC) failed");
        goto Exit;
    }

    EventFd = eventfd(0, EFD_CLOEXEC);
    if (EventFd == INVALID_SOCKET) {
        Status = errno;
        QuicTraceLogError(
            "LibraryErrorStatus: [lib] ERROR, %u, %s.",
            Status,
            "eventfd failed");
        goto Exit;
    }

    struct epoll_event EvtFdEpEvt = {
        .events = EPOLLIN,
        .data = {
            .ptr = NULL
        }
    };

    Ret = epoll_ctl(EpollFd, EPOLL_CTL_ADD, EventFd, &EvtFdEpEvt);
    if (Ret != 0) {
        Status = errno;
        QuicTraceLogError(
            "LibraryErrorStatus: [lib] ERROR, %u, %s.",
            Status,
            "epoll_ctl(EPOLL_CTL_ADD) failed");
        goto Exit;
    }

    EventFdAdded = TRUE;

    ProcContext->Datapath = Datapath;
    ProcContext->EpollFd = EpollFd;
    ProcContext->EventFd = EventFd;

    //
    // Starting the thread must be done after the rest of the ProcContext
    // members have been initialized. Because the thread start routine accesses
    // ProcContext members.
    //

    QUIC_THREAD_CONFIG ThreadConfig = {
        QUIC_THREAD_FLAG_SET_AFFINITIZE,
        (uint16_t)Index,
        NULL,
        QuicDataPathWorkerThread,
        ProcContext
    };

    Status = QuicThreadCreate(&ThreadConfig, &ProcContext->EpollWaitThread);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError(
            "LibraryErrorStatus: [lib] ERROR, %u, %s.",
            Status,
            "QuicThreadCreate failed");
        goto Exit;
    }
    ThreadCreated = true;

Exit:

    if (QUIC_FAILED(Status)) {
        if (ThreadCreated) {
             QuicProcessorContextUninitialize(ProcContext);
        } else {
			if (EventFdAdded) {
				epoll_ctl(EpollFd, EPOLL_CTL_DEL, EventFd, NULL);	
			}
        	if (EventFd != INVALID_SOCKET) {
            	close(EventFd);
        	}
        	if (EpollFd != INVALID_SOCKET) {
            	close(EpollFd);
        	}
        	QuicPoolUninitialize(&ProcContext->RecvBlockPool);
            QuicPoolUninitialize(&ProcContext->LargeSendBufferPool);
        	QuicPoolUninitialize(&ProcContext->SendBufferPool);
        	QuicPoolUninitialize(&ProcContext->SendDataPool);
    	}
	}
    return Status;
}


QUIC_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const QUIC_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const QUIC_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _Out_ QUIC_DATAPATH* *NewDataPath
    )
{

   UNREFERENCED_PARAMETER(TcpCallbacks);

    if (NewDataPath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (UdpCallbacks != NULL) {
        if (UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    size_t DatapathLength =
        sizeof(QUIC_DATAPATH) +
            QuicProcMaxCount() * sizeof(QUIC_DATAPATH_PROC_CONTEXT);

    QUIC_DATAPATH* Datapath = (QUIC_DATAPATH*)QUIC_ALLOC_PAGED(DatapathLength);
    if (Datapath == NULL) {
        QuicTraceLogError(
            "AllocFailure: Allocation of '%s' failed. (%lu bytes)",
            "QUIC_DATAPATH",
            DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(Datapath, DatapathLength);
	if (UdpCallbacks) {
		 Datapath->UdpHandlers = *UdpCallbacks;
	}

    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = QuicProcMaxCount();
    Datapath->MaxSendBatchSize = QUIC_MAX_BATCH_SEND;
    Datapath->Features = QUIC_DATAPATH_FEATURE_LOCAL_PORT_SHARING;
    QuicRundownInitialize(&Datapath->BindingsRundown);

#ifdef UDP_SEGMENT
    Status = QuicDataPathQuerySockoptSupport(Datapath);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
#endif

    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        Status = QuicProcessorContextInitialize(Datapath, i, &Datapath->ProcContexts[i]);
        if (QUIC_FAILED(Status)) {
            Datapath->Shutdown = TRUE;
            for (uint32_t j = 0; j < i; j++) {
                QuicProcessorContextUninitialize(&Datapath->ProcContexts[j]);
            }
            goto Exit;
        }
    }

    *NewDataPath = Datapath;
    Datapath = NULL;

Exit:

    if (Datapath != NULL) {
        QuicRundownUninitialize(&Datapath->BindingsRundown);
        QUIC_FREE(Datapath);
    }

    return Status;

}

void
QuicDataPathUninitialize(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }

    QuicRundownReleaseAndWait(&Datapath->BindingsRundown);

    Datapath->Shutdown = TRUE;
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        QuicProcessorContextUninitialize(&Datapath->ProcContexts[i]);
    }

    QuicRundownUninitialize(&Datapath->BindingsRundown);
    QUIC_FREE(Datapath);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    return Datapath->Features;
}

BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    return !!(Datapath->Features & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

QUIC_DATAPATH_RECV_BLOCK*
QuicDataPathAllocRecvBlock(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* DatapathProc
    )
{
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock = QuicPoolAlloc(&DatapathProc->RecvBlockPool);
    if (RecvBlock == NULL) {
        QuicTraceLogError(
            "AllocFailure: Allocation of '%s' failed. (%u bytes)",
            "QUIC_DATAPATH_RECV_BLOCK",
            0);
    } else {
        QuicZeroMemory(RecvBlock, sizeof(*RecvBlock));
        RecvBlock->OwningPool = &DatapathProc->RecvBlockPool;
        RecvBlock->RecvPacket.Buffer = RecvBlock->Buffer;
        RecvBlock->RecvPacket.Allocated = TRUE;
    }
    return RecvBlock;
}

void
QuicDataPathPopulateTargetAddress(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ ADDRINFO* AddrInfo,
    _Out_ QUIC_ADDR* Address
    )
{
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    QuicZeroMemory(Address, sizeof(QUIC_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        QUIC_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

        //
        // Is this a mapped ipv4 one?
        //

        SockAddrIn6 = (struct sockaddr_in6*)AddrInfo->ai_addr;

        if (Family == QUIC_ADDRESS_FAMILY_UNSPEC && IN6_IS_ADDR_V4MAPPED(&SockAddrIn6->sin6_addr)) {
            SockAddrIn = &Address->Ipv4;

            //
            // Get the ipv4 address from the mapped address.
            //

            SockAddrIn->sin_family = QUIC_ADDRESS_FAMILY_INET;
            memcpy(&SockAddrIn->sin_addr.s_addr, &SockAddrIn6->sin6_addr.s6_addr[12], 4);
            SockAddrIn->sin_port = SockAddrIn6->sin6_port;

            return;
        } else {
            Address->Ipv6 = *SockAddrIn6;
			Address->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
            return;
        }
    } else if (AddrInfo->ai_addr->sa_family == AF_INET) {
        QUIC_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
		Address->Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
        return;
    } 

    QUIC_FRE_ASSERT(FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
QuicDataPathGetLocalAddresses(
    _In_ QUIC_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        QUIC_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    *Addresses = NULL;
    *AddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
QuicDataPathGetGatewayAddresses(
    _In_ QUIC_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    *GatewayAddresses = NULL;
    *GatewayAddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
}


QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR * Address
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    ADDRINFO* AddrInfo = NULL;
    int Result = 0;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->Ip.sa_family;
   	if (Hints.ai_family == QUIC_ADDRESS_FAMILY_INET6) {
        Hints.ai_family = AF_INET6;
    } 
	
	//
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        QuicDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        QuicDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }


    QuicTraceLogError(
        "DatapathResolveHostNameFailed: [%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
    Status = (QUIC_STATUS)Result;

Exit:

    return Status;
}

QUIC_STATUS
QuicSocketConfigureRss(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ uint32_t SocketCount
    )
{
#ifdef SO_ATTACH_REUSEPORT_CBPF
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;

    struct sock_filter BpfCode[] = {
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF | SKF_AD_CPU},
        {BPF_ALU | BPF_MOD, 0, 0, SocketCount},
        {BPF_RET | BPF_A, 0, 0, 0}
    };

    struct sock_fprog BpfConfig = {
        .len = ARRAYSIZE(BpfCode),
        .filter = BpfCode
    };

    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_ATTACH_REUSEPORT_CBPF,
            (const void*)&BpfConfig,
            sizeof(BpfConfig));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed");
    }

    return Status;
#else
    UNREFERENCED_PARAMETER(SocketContext);
    UNREFERENCED_PARAMETER(SocketCount);
    return QUIC_STATUS_NOT_SUPPORTED;
#endif
}

//
// Socket context interface. It abstracts a (generally per-processor) UDP socket
// and the corresponding logic/functionality like send and receive processing.
//

QUIC_STATUS
QuicSocketContextInitialize(
    _Inout_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
	_In_ BOOLEAN ForceShare
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;
    int Option = 0;
    QUIC_ADDR MappedAddress;
    QuicZeroMemory(&MappedAddress, sizeof(QUIC_ADDR));
    socklen_t AssignedLocalAddressLength = 0;

   	QUIC_SOCKET* Binding = SocketContext->Binding;

    for (uint32_t i = 0; i < ARRAYSIZE(SocketContext->EventContexts); ++i) {
        SocketContext->EventContexts[i] = i;
    }

    SocketContext->CleanupFd = eventfd(0, EFD_CLOEXEC);
    if (SocketContext->CleanupFd == INVALID_SOCKET) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "eventfd failed");
        goto Exit;
    }

    struct epoll_event EvtFdEpEvt = {
        .events = EPOLLIN,
        .data = {
            .ptr = &SocketContext->EventContexts[QUIC_SOCK_EVENT_CLEANUP]
        }
    };

    if (epoll_ctl(
            SocketContext->ProcContext->EpollFd,
            EPOLL_CTL_ADD,
            SocketContext->CleanupFd,
            &EvtFdEpEvt) != 0) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "epoll_ctl(EPOLL_CTL_ADD) failed");
        goto Exit;
    }

    //
    // Create datagram socket.
    //
    SocketContext->SocketFd =
        socket(
            AF_INET6,
            SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, // TODO check if SOCK_CLOEXEC is required?
            IPPROTO_UDP);
    if (SocketContext->SocketFd == INVALID_SOCKET) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket failed");
        goto Exit;
    }
	
    //
    // Set dual (IPv4 & IPv6) socket mode.
    //
    Option = FALSE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_V6ONLY) failed");
        goto Exit;
    }

    //
    // Set DON'T FRAG socket option.
    //

    //
    // Windows: setsockopt IPPROTO_IP IP_DONTFRAGMENT TRUE.
    // Linux: IP_DONTFRAGMENT option is not available. IPV6_MTU_DISCOVER is the
    // apparent alternative.
    // TODO: Verify this.
    //
    Option = IP_PMTUDISC_DO;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_MTU_DISCOVER,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_MTU_DISCOVER) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_DONTFRAG,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_DONTFRAG) failed");
        goto Exit;
    }

    //
    // Set socket option to receive ancillary data about the incoming packets.
    //

    //
    // Windows: setsockopt IPPROTO_IPV6 IPV6_PKTINFO TRUE.
    // Android: Returns EINVAL. IPV6_PKTINFO option is not present in documentation.
    // IPV6_RECVPKTINFO seems like is the alternative.
    // TODO: Check if this works as expected?
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_RECVPKTINFO,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_RECVPKTINFO) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_PKTINFO,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_PKTINFO) failed");
        goto Exit;
    }

    //
    // Set socket option to receive TOS (= DSCP + ECN) information from the
    // incoming packet.
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_RECVTCLASS,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_RECVTCLASS) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_RECVTOS,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_RECVTOS) failed");
        goto Exit;
    }

    //
    // The socket is shared by multiple QUIC endpoints, so increase the receive
    // buffer size.
    //
    Option = INT32_MAX;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_RCVBUF,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_RCVBUF) failed");
        goto Exit;
    }

    //
    //Only set SO_REUSEPORT on a server socket, otherwise the client could be
    //assigned a server port (unless it's forcing sharing).
    //               

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_REUSEPORT,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_REUSEPORT) failed");
        goto Exit;
    }

    QuicCopyMemory(&MappedAddress, &Binding->LocalAddress, sizeof(MappedAddress));
    if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
        MappedAddress.Ipv6.sin6_family = AF_INET6;
    }

    Result =
        bind(
            SocketContext->SocketFd,
            &MappedAddress.Ip,
            sizeof(MappedAddress));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "bind failed");
        goto Exit;
    }

    if (RemoteAddress != NULL) {
        QuicZeroMemory(&MappedAddress, sizeof(MappedAddress));
        QuicConvertToMappedV6(RemoteAddress, &MappedAddress);

        if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }

        Result =
            connect(
                SocketContext->SocketFd,
                &MappedAddress.Ip,
                sizeof(MappedAddress));

        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceLogError(
                "DatapathErrorStatus: [udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "connect failed");
            goto Exit;
        }
		Binding->Connected = TRUE;
    }


    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //
    AssignedLocalAddressLength = sizeof(Binding->LocalAddress);
    Result =
        getsockname(
            SocketContext->SocketFd,
            (struct sockaddr *)&Binding->LocalAddress,
            &AssignedLocalAddressLength);
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceLogError(
            "DatapathErrorStatus: [udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "getsockname failed");
        goto Exit;
    }

#if DEBUG
    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        QUIC_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    } else if (RemoteAddress && LocalAddress && LocalAddress->Ipv4.sin_port == 0) {
        //
        //A client socket being assigned the same port as a remote socket causes issues later
        //in the datapath and binding paths. Check to make sure this case was not given to us.
        //                   
       QUIC_DBG_ASSERT(Binding->LocalAddress.Ipv4.sin_port != RemoteAddress->Ipv4.sin_port);
	}
#else 
	UNREFERENCED_PARAMETER(LocalAddress);
#endif


    if (Binding->LocalAddress.Ipv6.sin6_family == AF_INET6) {
        Binding->LocalAddress.Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }

Exit:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET;
    }

    return Status;
}

void
QuicSocketContextUninitialize(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{

    int EpollRes = epoll_ctl(SocketContext->ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);
    QUIC_FRE_ASSERT(EpollRes == 0);

    const eventfd_t Value = 1;
    eventfd_write(SocketContext->CleanupFd, Value);
}

void
QuicSocketContextUninitializeComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    for (ssize_t i =0;  i <QUIC_MAX_BATCH_RECEIVE; i++) {
		if (SocketContext->CurrentRecvBlocks[i] != NULL) {
        	QuicRecvDataReturn(&SocketContext->CurrentRecvBlocks[i]->RecvPacket);
		}
    }

    while (!QuicListIsEmpty(&SocketContext->PendingSendDataHead)) {
        QuicSendDataFree(
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&SocketContext->PendingSendDataHead),
                QUIC_SEND_DATA,
                PendingSendLinkage));
    }

	int EpollFd = SocketContext->ProcContext->EpollFd;
    epoll_ctl(EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);
    epoll_ctl(EpollFd, EPOLL_CTL_DEL, SocketContext->CleanupFd, NULL);
    close(SocketContext->CleanupFd);
    close(SocketContext->SocketFd);

    QuicRundownRelease(&SocketContext->Binding->Rundown);
}

QUIC_STATUS
QuicSocketContextPrepareReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{

    QuicZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    QuicZeroMemory(&SocketContext->RecvMsgControl, sizeof(SocketContext->RecvMsgControl));

	for (ssize_t i = 0; i< QUIC_MAX_BATCH_RECEIVE; i++) {
    	if (SocketContext->CurrentRecvBlocks[i] == NULL) {
        	SocketContext->CurrentRecvBlocks[i] =
            	QuicDataPathAllocRecvBlock(SocketContext->ProcContext);

        	if (SocketContext->CurrentRecvBlocks[i] == NULL) {
            	QuicTraceLogError(
                	"AllocFailure: Allocation of '%s' failed. (%u bytes)",
                	"QUIC_DATAPATH_RECV_BLOCK",
                	0);
            	return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    QUIC_DATAPATH_RECV_BLOCK* CurrentBlock = SocketContext->CurrentRecvBlocks[i];
    struct msghdr* MsgHdr = &SocketContext->RecvMsgHdr[i].msg_hdr;

    SocketContext->RecvIov[i].iov_base = CurrentBlock->RecvPacket.Buffer;
    CurrentBlock->RecvPacket.BufferLength = SocketContext->RecvIov[i].iov_len;
    CurrentBlock->RecvPacket.Tuple = &CurrentBlock->Tuple;

    MsgHdr->msg_name = &CurrentBlock->RecvPacket.Tuple->RemoteAddress;
    MsgHdr->msg_namelen = sizeof(CurrentBlock->RecvPacket.Tuple->RemoteAddress);
    MsgHdr->msg_iov = &SocketContext->RecvIov[i];
    MsgHdr->msg_iovlen = 1;
    MsgHdr->msg_control = &SocketContext->RecvMsgControl[i].Data;
    MsgHdr->msg_controllen = sizeof(SocketContext->RecvMsgControl[i].Data);
    MsgHdr->msg_flags = 0;
	}

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicSocketContextStartReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QuicSocketContextPrepareReceive(SocketContext);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    struct epoll_event SockFdEpEvt = {
        .events = EPOLLIN | EPOLLET,
        .data = {
            .ptr = &SocketContext->EventContexts[QUIC_SOCK_EVENT_SOCKET]
        }
    };

    int Ret =
        epoll_ctl(
            SocketContext->ProcContext->EpollFd,
            EPOLL_CTL_ADD,
            SocketContext->SocketFd,
            &SockFdEpEvt);
    if (Ret != 0) {
        Status = Ret;
        QuicTraceLogError(
            "DatapathErrorStatus: [udp][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "epoll_ctl failed");

        //
        //Return any allocations
        //               
        for (ssize_t i = 0; i < QUIC_MAX_BATCH_RECEIVE; i++) {
            if (SocketContext->CurrentRecvBlocks[i] != NULL) {
                QuicRecvDataReturn(&SocketContext->CurrentRecvBlocks[i]->RecvPacket);
            }
        }

        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET;
    }

    return Status;
}

void
QuicSocketContextRecvComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
   	_In_ int MessagesReceived
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
	uint32_t BytesTransferred = 0;

    QUIC_DBG_ASSERT(MessagesReceived <= QUIC_MAX_BATCH_RECEIVE);

    QUIC_RECV_DATA* DatagramHead = NULL;
    QUIC_RECV_DATA* DatagramTail = NULL;

    for (int CurrentMessage = 0; CurrentMessage < MessagesReceived; CurrentMessage++) {
        QUIC_DATAPATH_RECV_BLOCK* CurrentBlock = SocketContext->CurrentRecvBlocks[CurrentMessage];
        SocketContext->CurrentRecvBlocks[CurrentMessage] = NULL;
        QUIC_RECV_DATA* RecvPacket = &CurrentBlock->RecvPacket;

        if (DatagramHead == NULL) {
            DatagramHead = RecvPacket;
            DatagramTail = DatagramHead;
        } else {
            DatagramTail->Next = RecvPacket;
            DatagramTail = DatagramTail->Next;
        }
        BOOLEAN FoundLocalAddr = FALSE;
        BOOLEAN FoundTOS = FALSE;
        QUIC_ADDR* LocalAddr = &RecvPacket->Tuple->LocalAddress;
        if (LocalAddr->Ipv6.sin6_family == AF_INET6) {
            LocalAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        }
        QUIC_ADDR* RemoteAddr = &RecvPacket->Tuple->RemoteAddress;
        if (RemoteAddr->Ipv6.sin6_family == AF_INET6) {
            RemoteAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        }
        QuicConvertFromMappedV6(RemoteAddr, RemoteAddr);

        RecvPacket->BufferLength = SocketContext->RecvMsgHdr[CurrentMessage].msg_len;
        BytesTransferred += RecvPacket->BufferLength;

    	RecvPacket->TypeOfService = 0;

    	struct cmsghdr *CMsg;
        struct msghdr* Msg = &SocketContext->RecvMsgHdr[CurrentMessage].msg_hdr;
    	for (CMsg = CMSG_FIRSTHDR(Msg);
        	 CMsg != NULL;
         	CMsg = CMSG_NXTHDR(Msg, CMsg)) {

        	if (CMsg->cmsg_level == IPPROTO_IPV6) {
            	if (CMsg->cmsg_type == IPV6_PKTINFO) {
                	struct in6_pktinfo* PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
                	LocalAddr->Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
                	LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
                	LocalAddr->Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                	QuicConvertFromMappedV6(LocalAddr, LocalAddr);

                	LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                	FoundLocalAddr = TRUE;
            	} else if (CMsg->cmsg_type == IPV6_TCLASS) {
                	RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                	FoundTOS = TRUE;
            	}
        	} else if (CMsg->cmsg_level == IPPROTO_IP) {
            	if (CMsg->cmsg_type == IP_PKTINFO) {
                	struct in_pktinfo* PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
                	LocalAddr->Ip.sa_family = QUIC_ADDRESS_FAMILY_INET;
                	LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
                	LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                	LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
                	FoundLocalAddr = TRUE;
            	} else if (CMsg->cmsg_type == IP_TOS) {
                	RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                	FoundTOS = TRUE;
            	}
        	}
    	}	

    	QUIC_FRE_ASSERT(FoundLocalAddr);
    	QUIC_FRE_ASSERT(FoundTOS);
    	RecvPacket->PartitionIndex = SocketContext->ProcContext->Index;

    	QuicTraceLogVerbose(
        	"DatapathRecv: [udp][%p] Recv %u bytes (segment=%hu) Src(addr:%p length:%lu) Dst(addr:%p, length:%lu)",
        	SocketContext->Binding,
        	(uint32_t)BytesTransferred,
        	(uint32_t)BytesTransferred,
        	LocalAddr, sizeof(*LocalAddr),
        	RemoteAddr, sizeof(*RemoteAddr));
	}

    if (BytesTransferred == 0 || DatagramHead == NULL) {
        QuicTraceLogWarning(
            "[data][%p] Dropping datagram with empty payload.",
            SocketContext->Binding);
        goto Drop;
    }

    if (!SocketContext->Binding->PcpBinding) {
        QUIC_DBG_ASSERT(SocketContext->Binding->Datapath->UdpHandlers.Receive);
        SocketContext->Binding->Datapath->UdpHandlers.Receive(
            SocketContext->Binding,
            SocketContext->Binding->ClientContext,
            DatagramHead);
	} else {
		
		#if 0
        QuicPcpRecvCallback(
            SocketContext->Binding,
            SocketContext->Binding->ClientContext,
            DatagramHead);
		#endif 
    }

Drop: ;

	int32_t RetryCount = 0;
    do {
        Status = QuicSocketContextPrepareReceive(SocketContext);
    } while (!QUIC_SUCCEEDED(Status) && RetryCount < 10);

    if (!QUIC_SUCCEEDED(Status)) {
        QuicTraceLogError(
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "QuicSocketContextPrepareReceive failed multiple times. Receive will no longer work.");
    }

}

//
// N.B Requires SocketContext->PendingSendDataLock to be locked.
//
void
QuicSocketContextPendSend(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
	_In_ QUIC_SEND_DATA* SendData,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{

	if (LocalAddress != NULL) {
    	QuicCopyMemory(
        	&SendData->LocalAddress,
            LocalAddress,
            sizeof(*LocalAddress));
    	SendData->Bind = TRUE;
    }

	QuicCopyMemory(
		&SendData->RemoteAddress,
        RemoteAddress,
        sizeof(*RemoteAddress));

    // This is a new send that wasn't previously pended. Add it to the end
    //of the queue.
    //        
    QuicListInsertTail(
        &SocketContext->PendingSendDataHead,
        &SendData->PendingSendLinkage);
}


QUIC_STATUS
QuicSocketContextSendComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
	QUIC_SEND_DATA* SendData = NULL;


  	struct epoll_event SockFdEpEvt = {
    	.events = EPOLLIN | EPOLLET,
      	.data = {
                .ptr = &SocketContext->EventContexts[QUIC_SOCK_EVENT_SOCKET]
            }
        };

	int Ret =
		epoll_ctl(
      		SocketContext->ProcContext->EpollFd,
            EPOLL_CTL_MOD,
            SocketContext->SocketFd,
            &SockFdEpEvt);

    if (Ret != 0) {
    	Status = Ret;
        QuicTraceLogError(
       	"DatapathErrorStatus: [udp][%p] ERROR, %u, %s.",
        SocketContext->Binding,
        Status,
       	"epoll_ctl failed");

		return Status;
	}
        
   
    QuicLockAcquire(&SocketContext->PendingSendDataLock);
	if (!QuicListIsEmpty(&SocketContext->PendingSendDataHead)) {
		SendData =
            QUIC_CONTAINING_RECORD(
                SocketContext->PendingSendDataHead.Flink,
                QUIC_SEND_DATA,
                PendingSendLinkage);
    }

    QuicLockRelease(&SocketContext->PendingSendDataLock);
    if (SendData == NULL) {
        return Status;
    }

	do {
        Status =
            QuicSocketSendInternal(
                SocketContext->Binding,
                SendData->Bind ? &SendData->LocalAddress : NULL,
                &SendData->RemoteAddress,
                SendData,
                TRUE);
        QuicLockAcquire(&SocketContext->PendingSendDataLock);
        if (Status != QUIC_STATUS_PENDING) {
            QuicListRemoveHead(&SocketContext->PendingSendDataHead);
            QuicSendDataFree(SendData);
            if (!QuicListIsEmpty(&SocketContext->PendingSendDataHead)) {
                SendData =
                    QUIC_CONTAINING_RECORD(
                        SocketContext->PendingSendDataHead.Flink,
                        QUIC_SEND_DATA,
                        PendingSendLinkage);
            } else {
                SendData = NULL;
            }
        }
        QuicLockRelease(&SocketContext->PendingSendDataLock);
    } while (Status == QUIC_STATUS_SUCCESS && SendData != NULL);

    return Status;
}		

void
QuicSocketContextProcessEvents(
    _In_ void* EventPtr,
    _In_ int Events
    )
{
    uint8_t EventType = *(uint8_t*)EventPtr;
    QUIC_SOCKET_CONTEXT* SocketContext =
        (QUIC_SOCKET_CONTEXT*)(
            (uint8_t*)QUIC_CONTAINING_RECORD(EventPtr, QUIC_SOCKET_CONTEXT, EventContexts) -
            EventType);

    if (EventType == QUIC_SOCK_EVENT_CLEANUP) {
        QUIC_DBG_ASSERT(SocketContext->Binding->Shutdown);
        QuicSocketContextUninitializeComplete(SocketContext);
        return;
    }

    QUIC_DBG_ASSERT(EventType == QUIC_SOCK_EVENT_SOCKET);

    if (EPOLLERR & Events) {
        int ErrNum = 0;
        socklen_t OptLen = sizeof(ErrNum);
        ssize_t Ret =
            getsockopt(
                SocketContext->SocketFd,
                SOL_SOCKET,
                SO_ERROR,
                &ErrNum,
                &OptLen);
        if (Ret < 0) {
            QuicTraceLogError(
                "DatapathErrorStatus: [udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                errno,
                "getsockopt(SO_ERROR) failed");
        } else {
            QuicTraceLogError(
                "DatapathErrorStatus: [udp][%p] ERROR, %u, %s ",
                SocketContext->Binding,
                ErrNum,
                "Socket error event");

            //
            // Send unreachable notification to MsQuic if any related
            // errors were received.
            //
            if (ErrNum == ECONNREFUSED ||
                ErrNum == EHOSTUNREACH ||
                ErrNum == ENETUNREACH) {
				if (!SocketContext->Binding->PcpBinding) {
                	SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
                    SocketContext->Binding,
                    SocketContext->Binding->ClientContext,
                    &SocketContext->Binding->RemoteAddress);
				}
            }
        }
    }

    if (EPOLLIN & Events) {
        while (TRUE) {
			for (ssize_t i = 0; i < QUIC_MAX_BATCH_RECEIVE; i++) {
            	QUIC_DBG_ASSERT(SocketContext->CurrentRecvBlocks[i] != NULL);
			}

            int Ret =
                recvmmsg(
                    SocketContext->SocketFd,
                    SocketContext->RecvMsgHdr,
					QUIC_MAX_BATCH_RECEIVE,
                    0,
					NULL);

            if (Ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    QuicTraceLogError(
                        "DatapathErrorStatus: [udp][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        errno,
                        "recvmsg failed");
                }
                break;
            } 
           	QuicSocketContextRecvComplete(SocketContext, Ret);
        }
    }

    if (EPOLLOUT & Events) {
        QuicSocketContextSendComplete(SocketContext);
    }
}

//
// Datapath binding interface.
//
QUIC_STATUS
QuicSocketCreateUdp(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ const QUIC_UDP_CONFIG* Config,
    _Out_ QUIC_SOCKET** NewBinding
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN IsServerSocket = Config->RemoteAddress == NULL;
    int32_t SuccessfulStartReceives = -1;

    QUIC_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL || Config->Flags & QUIC_SOCKET_FLAG_PCP);

    uint32_t SocketCount = IsServerSocket ? Datapath->ProcCount : 1;
    uint32_t CurrentProc = QuicProcCurrentNumber() % Datapath->ProcCount;
    QUIC_FRE_ASSERT(SocketCount > 0);
    size_t BindingLength =
        sizeof(QUIC_SOCKET) +
        SocketCount * sizeof(QUIC_SOCKET_CONTEXT);

    QUIC_SOCKET* Binding =
        (QUIC_SOCKET*)QUIC_ALLOC_PAGED(BindingLength);
    if (Binding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError(
            "Allocation of '%s' failed. (%lu bytes)",
            "CXPLAT_SOCKET",
            BindingLength);
        goto Exit;
    }

    QuicZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = Config->CallbackContext;
    Binding->HasFixedRemoteAddress = (Config->RemoteAddress != NULL);
    Binding->Mtu = QUIC_MAX_MTU;
    QuicRundownInitialize(&Binding->Rundown);
    if (Config->LocalAddress) {
        QuicConvertToMappedV6(Config->LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET;
		Binding->SocketContexts[i].CleanupFd = INVALID_SOCKET;
		for (ssize_t j = 0; j < QUIC_MAX_BATCH_RECEIVE; j++) {
        	Binding->SocketContexts[i].RecvIov[j].iov_len =
            	Binding->Mtu - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE;
		}
        Binding->SocketContexts[i].ProcContext = &Datapath->ProcContexts[IsServerSocket ? i : CurrentProc];
        QuicListInitializeHead(&Binding->SocketContexts[i].PendingSendDataHead);
        QuicLockInitialize(&Binding->SocketContexts[i].PendingSendDataLock);
        QuicRundownAcquire(&Binding->Rundown);
    }

    QuicRundownAcquire(&Datapath->BindingsRundown);
    if (Config->Flags & QUIC_SOCKET_FLAG_PCP) {
        Binding->PcpBinding = TRUE;
    }

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            QuicSocketContextInitialize(
                &Binding->SocketContexts[i],
                Config->LocalAddress,
                Config->RemoteAddress,
				Config->Flags & QUIC_SOCKET_FLAG_SHARE);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    if (IsServerSocket) {
        //
        //The return value is being ignored here, as if a system does not support
        //bpf we still want the server to work. If this happens, the sockets will
        //round robin, but each flow will be sent to the same socket, just not
        //based on RSS.
        //                                       
        (void)QuicSocketConfigureRss(&Binding->SocketContexts[0], SocketCount);
    }


    QuicConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (Config->RemoteAddress != NULL) {
        Binding->RemoteAddress = *Config->RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    //Must set output pointer before starting receive path, as the receive path
    //will try to use the output.
    //           
    *NewBinding = Binding;

    SuccessfulStartReceives = 0;
    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            QuicSocketContextStartReceive(
                &Binding->SocketContexts[i]);
        if (QUIC_FAILED(Status)) {
            SuccessfulStartReceives = (int32_t)i;
            goto Exit;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        if (Binding != NULL) {
            QuicTraceLogError(
                "[data][%p] Destroyed",
                Binding);

            if (SuccessfulStartReceives >= 0) {
                uint32_t CurrentSocket = 0;
                Binding->Shutdown = TRUE;
                //
                //First shutdown any sockets that fully started
                //                               
                for (; CurrentSocket < (uint32_t)SuccessfulStartReceives; CurrentSocket++) {
                    QuicSocketContextUninitialize(&Binding->SocketContexts[CurrentSocket]);
                }
                //
                //Then shutdown any sockets that failed to start
                //                             
                for (; CurrentSocket < SocketCount; CurrentSocket++) {
                    QuicSocketContextUninitializeComplete(&Binding->SocketContexts[CurrentSocket]);
                }
            } else {
                //
                //No sockets fully started. Only uninitialize static things
                //                             
                for (uint32_t i = 0; i < SocketCount; i++) {
                    QUIC_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];
                    int EpollFd = SocketContext->ProcContext->EpollFd;
                    if (SocketContext->CleanupFd != INVALID_SOCKET) {
                        epoll_ctl(EpollFd, EPOLL_CTL_DEL, SocketContext->CleanupFd, NULL);
                        close(SocketContext->CleanupFd);
                    }
                    if (SocketContext->SocketFd != INVALID_SOCKET) {
                        epoll_ctl(EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);
                        close(SocketContext->SocketFd);
                    }
                    QuicRundownRelease(&Binding->Rundown);
                }
            }
            QuicRundownReleaseAndWait(&Binding->Rundown);
            QuicRundownRelease(&Datapath->BindingsRundown);
            QuicRundownUninitialize(&Binding->Rundown);
            for (uint32_t i = 0; i < SocketCount; i++) {
                QuicLockUninitialize(&Binding->SocketContexts[i].PendingSendDataLock);
            }
            QUIC_FREE(Binding);
            Binding = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSocketCreateTcp(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ QUIC_SOCKET** Socket
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(RemoteAddress);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Socket);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSocketCreateTcpListener(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* CallbackContext,
    _Out_ QUIC_SOCKET** Socket
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Socket);
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
QuicSocketDelete(
    _Inout_ QUIC_SOCKET* Socket
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);
    QuicTraceLogInfo(
        "[data][%p] Destroyed",
        Socket);

    //
    //The function is called by the upper layer when it is completely done
    //with the UDP binding. It expects that after this call returns there will
    //be no additional upcalls related to this binding, and all outstanding
    //upcalls on different threads will be completed.
    //           
     
    Socket->Shutdown = TRUE;
    uint32_t SocketCount = Socket->HasFixedRemoteAddress ? 1 : Socket->Datapath->ProcCount;
    for (uint32_t i = 0; i < SocketCount; ++i) {
        QuicSocketContextUninitialize(
            &Socket->SocketContexts[i]);
    }

    QuicRundownReleaseAndWait(&Socket->Rundown);
    QuicRundownRelease(&Socket->Datapath->BindingsRundown);

    QuicRundownUninitialize(&Socket->Rundown);
    for (uint32_t i = 0; i < SocketCount; i++) {
        QuicLockUninitialize(&Socket->SocketContexts[i].PendingSendDataLock);
    }
    QUIC_FREE(Socket);
}
	

void
QuicSocketGetLocalAddress(
    _In_ QUIC_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);
    *Address = Socket->LocalAddress;
}

void
QuicSocketGetRemoteAddress(
    _In_ QUIC_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);
    *Address = Socket->RemoteAddress;
}

QUIC_STATUS
QuicSocketSetParam(
    _In_ QUIC_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
QuicSocketGetParam(
    _In_ QUIC_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_RECV_DATA*
QuicDataPathRecvPacketToRecvData(
    _In_ const QUIC_RECV_PACKET* const Packet
    )
{
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        (QUIC_DATAPATH_RECV_BLOCK*)
            ((char *)Packet - sizeof(QUIC_DATAPATH_RECV_BLOCK));

    return &RecvBlock->RecvPacket;
}

QUIC_RECV_PACKET*
QuicDataPathRecvDataToRecvPacket(
    _In_ const QUIC_RECV_DATA* const RecvData
    )
{
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        QUIC_CONTAINING_RECORD(RecvData, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);

    return (QUIC_RECV_PACKET*)(RecvBlock + 1);
}

void
QuicRecvDataReturn(
    _In_opt_ QUIC_RECV_DATA* RecvDataChain
    )
{
    QUIC_RECV_DATA* Datagram;
    while ((Datagram = RecvDataChain) != NULL) {
        RecvDataChain = RecvDataChain->Next;
        QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
            QUIC_CONTAINING_RECORD(Datagram, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);
        QuicPoolFree(RecvBlock->OwningPool, RecvBlock);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SEND_DATA*
QuicSendDataAlloc(
    _In_ QUIC_SOCKET* Socket,
    _In_ QUIC_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);

    QUIC_DATAPATH_PROC_CONTEXT* DatapathProc =
        &Socket->Datapath->ProcContexts[QuicProcCurrentNumber() % Socket->Datapath->ProcCount];

    QUIC_SEND_DATA* SendData =
        QuicPoolAlloc(&DatapathProc->SendDataPool);

    if (SendData == NULL) {
        QuicTraceLogError(
            "Allocation of '%s' failed. (%d bytes)",
            "CXPLAT_SEND_DATA",
            0);
        goto Exit;
    }

    QuicZeroMemory(SendData, sizeof(*SendData));

    SendData->Owner = DatapathProc;
    SendData->ECN = ECN;
    SendData->SegmentSize =
        (Socket->Datapath->Features & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION)
            ? MaxPacketSize : 0;

Exit:
    return SendData;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendDataFree(
    _In_ QUIC_SEND_DATA* SendData
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* DatapathProc = SendData->Owner;
    QUIC_POOL* BufferPool =
        SendData->SegmentSize > 0 ?
            &DatapathProc->LargeSendBufferPool : &DatapathProc->SendBufferPool;

    for (size_t i = 0; i < SendData->BufferCount; ++i) {
        QuicPoolFree(BufferPool, SendData->Buffers[i].Buffer);
    }

    QuicPoolFree(&DatapathProc->SendDataPool, SendData);
}

BOOLEAN
QuicSendDataCanAllocSendSegment(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    if (!SendData->ClientBuffer.Buffer) {
        return FALSE;
    }

    QUIC_DBG_ASSERT(SendData->SegmentSize > 0);
    QUIC_DBG_ASSERT(SendData->BufferCount > 0);

    uint64_t BytesAvailable =
        QUIC_LARGE_SEND_BUFFER_SIZE -
            SendData->Buffers[SendData->BufferCount - 1].Length -
            SendData->ClientBuffer.Length;

    return MaxBufferLength <= BytesAvailable;
}

BOOLEAN
QuicSendDataCanAllocSend(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    return
        (SendData->BufferCount < SendData->Owner->Datapath->MaxSendBatchSize) ||
        ((SendData->SegmentSize > 0) &&
            QuicSendDataCanAllocSendSegment(SendData, MaxBufferLength));
}

void
QuicSendDataFinalizeSendBuffer(
    _In_ QUIC_SEND_DATA* SendData
    )
{
    if (SendData->ClientBuffer.Length == 0) {
        //
        //There is no buffer segment outstanding at the client.
        //              
        if (SendData->BufferCount > 0) {
            QUIC_DBG_ASSERT(SendData->Buffers[SendData->BufferCount - 1].Length < UINT16_MAX);
            SendData->TotalSize +=
                SendData->Buffers[SendData->BufferCount - 1].Length;
        }
        return;
    }

    QUIC_DBG_ASSERT(SendData->SegmentSize > 0 && SendData->BufferCount > 0);
    QUIC_DBG_ASSERT(SendData->ClientBuffer.Length > 0 && SendData->ClientBuffer.Length <= SendData->SegmentSize);
    QUIC_DBG_ASSERT(QuicSendDataCanAllocSendSegment(SendData, 0));
    //
    //Append the client's buffer segment to our internal send buffer.
    //        
    SendData->Buffers[SendData->BufferCount - 1].Length +=
        SendData->ClientBuffer.Length;
    SendData->TotalSize += SendData->ClientBuffer.Length;

    if (SendData->ClientBuffer.Length == SendData->SegmentSize) {
        SendData->ClientBuffer.Buffer += SendData->SegmentSize;
        SendData->ClientBuffer.Length = 0;
    } else {
        //
        //The next segment allocation must create a new backing buffer.
        //               
        SendData->ClientBuffer.Buffer = NULL;
        SendData->ClientBuffer.Length = 0;
    }
}

_Success_(return != NULL)
QUIC_BUFFER*
QuicSendDataAllocDataBuffer(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ QUIC_POOL* BufferPool
    )
{
    QUIC_DBG_ASSERT(SendData->BufferCount < SendData->Owner->Datapath->MaxSendBatchSize);

    QUIC_BUFFER* Buffer = &SendData->Buffers[SendData->BufferCount];
    Buffer->Buffer = QuicPoolAlloc(BufferPool);
    if (Buffer->Buffer == NULL) {
        return NULL;
    }
    ++SendData->BufferCount;

    return Buffer;
}

_Success_(return != NULL)
QUIC_BUFFER*
QuicSendDataAllocPacketBuffer(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    QUIC_BUFFER* Buffer =
        QuicSendDataAllocDataBuffer(SendData, &SendData->Owner->SendBufferPool);
    if (Buffer != NULL) {
        Buffer->Length = MaxBufferLength;
    }
    return Buffer;
}

_Success_(return != NULL)
QUIC_BUFFER*
QuicSendDataAllocSegmentBuffer(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    QUIC_DBG_ASSERT(SendData->SegmentSize > 0);
    QUIC_DBG_ASSERT(MaxBufferLength <= SendData->SegmentSize);

    if (QuicSendDataCanAllocSendSegment(SendData, MaxBufferLength)) {
        //
        //All clear to return the next segment of our contiguous buffer.
        //                
        SendData->ClientBuffer.Length = MaxBufferLength;
        return &SendData->ClientBuffer;
    }

    QUIC_BUFFER* Buffer = QuicSendDataAllocDataBuffer(SendData, &SendData->Owner->LargeSendBufferPool);
    if (Buffer == NULL) {
        return NULL;
    }

    //
    //Provide a virtual QUIC_BUFFER to the client. Once the client has committed
    //to a final send size, we'll append it to our internal backing buffer.
    //          
    Buffer->Length = 0;
    SendData->ClientBuffer.Buffer = Buffer->Buffer;
    SendData->ClientBuffer.Length = MaxBufferLength;

    return &SendData->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
QuicSendDataAllocBuffer(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    QUIC_DBG_ASSERT(SendData != NULL);
    QUIC_DBG_ASSERT(MaxBufferLength > 0);
    QuicSendDataFinalizeSendBuffer(SendData);

    if (!QuicSendDataCanAllocSend(SendData, MaxBufferLength)) {
        return NULL;
    }

    if (SendData->SegmentSize == 0) {
        return QuicSendDataAllocPacketBuffer(SendData, MaxBufferLength);
    }
    return QuicSendDataAllocSegmentBuffer(SendData, MaxBufferLength);
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendDataFreeBuffer(
    _In_ QUIC_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    //
    //This must be the final send buffer; intermediate buffers cannot be freed.
    //       
    QUIC_DATAPATH_PROC_CONTEXT* DatapathProc = SendData->Owner;
    uint8_t* TailBuffer = SendData->Buffers[SendData->BufferCount - 1].Buffer;

    if (SendData->SegmentSize == 0) {
        QUIC_DBG_ASSERT(Buffer->Buffer == (uint8_t*)TailBuffer);

        QuicPoolFree(&DatapathProc->SendBufferPool, Buffer->Buffer);
        --SendData->BufferCount;
    } else {
        TailBuffer += SendData->Buffers[SendData->BufferCount - 1].Length;
        QUIC_DBG_ASSERT(Buffer->Buffer == (uint8_t*)TailBuffer);

        if (SendData->Buffers[SendData->BufferCount - 1].Length == 0) {
            QuicPoolFree(&DatapathProc->LargeSendBufferPool, Buffer->Buffer);
            --SendData->BufferCount;
        }

        SendData->ClientBuffer.Buffer = NULL;
        SendData->ClientBuffer.Length = 0;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSendDataIsFull(
    _In_ QUIC_SEND_DATA* SendData
    )
{
    return !QuicSendDataCanAllocSend(SendData, SendData->SegmentSize);
}

void
QuicSendDataComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketProc,
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint64_t IoResult
    )
{
    if (IoResult != QUIC_STATUS_SUCCESS) {
        QuicTraceLogInfo(
            "[data][%p] ERROR, %lu, %s.",
            SocketProc->Binding,
            IoResult,
            "sendmmsg completion");
    }

    // TODO to add TCP
    //if (SocketProc->Parent->Type != CXPLAT_SOCKET_UDP) {
    //SocketProc->Parent->Datapath->TcpHandlers.SendComplete(
    //SocketProc->Parent,
    //SocketProc->Parent->ClientContext,
    //IoResult,
    //SendData->TotalSize);
    //            


    QuicSendDataFree(SendData);
}

QUIC_STATUS
QuicSocketSendInternal(
    _In_ QUIC_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_SEND_DATA* SendData,
    _In_ BOOLEAN IsPendedSend
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_SOCKET_CONTEXT* SocketContext = NULL;
    QUIC_ADDR MappedRemoteAddress;
    struct cmsghdr *CMsg = NULL;
    struct in_pktinfo *PktInfo = NULL;
    struct in6_pktinfo *PktInfo6 = NULL;
    BOOLEAN SendPending = FALSE;
    size_t TotalMessagesCount;

	memset(&MappedRemoteAddress, 0, sizeof(QUIC_ADDR));
    QUIC_DBG_ASSERT(Socket != NULL && RemoteAddress != NULL && SendData != NULL);
    QUIC_DBG_ASSERT(SendData->SentMessagesCount < QUIC_MAX_BATCH_SEND);
    QUIC_DBG_ASSERT(IsPendedSend || SendData->SentMessagesCount == 0);

    QUIC_STATIC_ASSERT(
        CMSG_SPACE(sizeof(struct in6_pktinfo)) >= CMSG_SPACE(sizeof(struct in_pktinfo)),
        "sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo) failed");
    char ControlBuffer[
        CMSG_SPACE(sizeof(struct in6_pktinfo)) +
        CMSG_SPACE(sizeof(int))
    #ifdef UDP_SEGMENT
        + CMSG_SPACE(sizeof(uint16_t))
    #endif
        ] = {0};

    if (Socket->HasFixedRemoteAddress) {
        SocketContext = &Socket->SocketContexts[0];
    } else {
        uint32_t ProcNumber = QuicProcCurrentNumber() % Socket->Datapath->ProcCount;
        SocketContext = &Socket->SocketContexts[ProcNumber];
    }

    if (!IsPendedSend) {
        QuicSendDataFinalizeSendBuffer(SendData);
        for (size_t i = SendData->SentMessagesCount; i < SendData->BufferCount; ++i) {
            SendData->Iovs[i].iov_base = SendData->Buffers[i].Buffer;
            SendData->Iovs[i].iov_len = SendData->Buffers[i].Length;
        }
        QuicTraceLogInfo(
            "[data][%p] Send %u bytes in %lu buffers (segment=%hu)",
            Socket,
            SendData->TotalSize,
            SendData->BufferCount,
            SendData->SegmentSize);

        //
        //Check to see if we need to pend.
        //              
        QuicLockAcquire(&SocketContext->PendingSendDataLock);
        if (!QuicListIsEmpty(&SocketContext->PendingSendDataHead)) {
            QuicSocketContextPendSend(
                SocketContext,
                SendData,
                LocalAddress,
                RemoteAddress);
            SendPending = TRUE;
        }
        QuicLockRelease(&SocketContext->PendingSendDataLock);
        if (SendPending) {
            Status = QUIC_STATUS_PENDING;
            goto Exit;
        }
    }

    //
    //Map V4 address to dual-stack socket format.
    //        
    QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

    if (MappedRemoteAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
        MappedRemoteAddress.Ipv6.sin6_family = AF_INET6;
    }

    struct mmsghdr Mhdrs[QUIC_MAX_BATCH_SEND];
    for (TotalMessagesCount = SendData->SentMessagesCount; TotalMessagesCount < SendData->BufferCount; TotalMessagesCount++) {
        struct msghdr TempMhdr = {
            .msg_name = &MappedRemoteAddress,
            .msg_namelen = sizeof(MappedRemoteAddress),
            .msg_iov = SendData->Iovs + TotalMessagesCount,
            .msg_iovlen = 1, 
            .msg_control = ControlBuffer,
            .msg_controllen = CMSG_SPACE(sizeof(int)),
            .msg_flags = 0
        };

        Mhdrs[TotalMessagesCount].msg_hdr = TempMhdr;

        struct msghdr* Mhdr = &Mhdrs[TotalMessagesCount].msg_hdr;
        Mhdrs[TotalMessagesCount].msg_len = 0;

        CMsg = CMSG_FIRSTHDR(Mhdr);
        CMsg->cmsg_level = RemoteAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET ? IPPROTO_IP : IPPROTO_IPV6;
        CMsg->cmsg_type = RemoteAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET ? IP_TOS : IPV6_TCLASS;
        CMsg->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(CMsg) = SendData->ECN;

        if (!Socket->Connected) {
            Mhdr->msg_controllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
            CMsg = CMSG_NXTHDR(Mhdr, CMsg);
            QUIC_DBG_ASSERT(LocalAddress != NULL);
            QUIC_DBG_ASSERT(CMsg != NULL);
            if (RemoteAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
                CMsg->cmsg_level = IPPROTO_IP;
                CMsg->cmsg_type = IP_PKTINFO;
                CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
                PktInfo = (struct in_pktinfo*) CMSG_DATA(CMsg);
                /*TODO: Use Ipv4 instead of Ipv6. */
                PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
                PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;
            } else {
                CMsg->cmsg_level = IPPROTO_IPV6;
                CMsg->cmsg_type = IPV6_PKTINFO;
                CMsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
                PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
                PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
            }
        }

#ifdef UDP_SEGMENT
        if (SendData->SegmentSize > 0 && (SendData->Iovs + TotalMessagesCount)->iov_len > SendData->SegmentSize) {
            Mhdr->msg_controllen += CMSG_SPACE(sizeof(uint16_t));
            CMsg = CMSG_NXTHDR(Mhdr, CMsg);
            CXPLAT_DBG_ASSERT(CMsg != NULL);
            CMsg->cmsg_level = SOL_UDP;
            CMsg->cmsg_type = UDP_SEGMENT;
            CMsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
            *((uint16_t*) CMSG_DATA(CMsg)) = SendData->SegmentSize;
        }
#endif
    }

    while (SendData->SentMessagesCount < TotalMessagesCount) {

        int SuccessfullySentMessages =
            QUIC_SENDMMSG(
                SocketContext->SocketFd,
                Mhdrs + SendData->SentMessagesCount,
                (unsigned int)(TotalMessagesCount - SendData->SentMessagesCount),
                0);

        QUIC_FRE_ASSERT(SuccessfullySentMessages != 0);

        if (SuccessfullySentMessages < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!IsPendedSend) {
                    QuicLockAcquire(&SocketContext->PendingSendDataLock);
                    QuicSocketContextPendSend(
                        SocketContext,
                        SendData,
                        LocalAddress,
                        RemoteAddress);
                    QuicLockRelease(&SocketContext->PendingSendDataLock);
                }
                SendPending = TRUE;
                struct epoll_event SockFdEpEvt = {
                    .events = EPOLLIN | EPOLLOUT | EPOLLET,
                    .data = {
                        .ptr = &SocketContext->EventContexts[QUIC_SOCK_EVENT_SOCKET]
                    }
                };

                int Ret =
                    epoll_ctl(
                        SocketContext->ProcContext->EpollFd,
                        EPOLL_CTL_MOD,
                        SocketContext->SocketFd,
                        &SockFdEpEvt);
                if (Ret != 0) {
                    QuicTraceLogError(
                        "[data][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        errno,
                        "epoll_ctl failed");
                    Status = errno;
                    goto Exit;
                }
                Status = QUIC_STATUS_PENDING;
                goto Exit;
            } else {
                Status = errno;
                QuicTraceLogError(
                    "[data][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "sendmmsg failed");
                //
                //Unreachable events can sometimes come synchronously.
                //Send unreachable notification to MsQuic if any related
                //errors were received.
                //                                                              
                if (Status == ECONNREFUSED ||
                    Status == EHOSTUNREACH ||
                    Status == ENETUNREACH) {
                    if (!SocketContext->Binding->PcpBinding) {
                        SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
                            SocketContext->Binding,
                            SocketContext->Binding->ClientContext,
                            &SocketContext->Binding->RemoteAddress);
                    }
                }
                goto Exit;
            }
        } else {
            SendData->SentMessagesCount += SuccessfullySentMessages;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (!SendPending && !IsPendedSend) {
        QuicSendDataComplete(SocketContext, SendData, Status);
    }

    return Status;
}


QUIC_STATUS
QuicSocketSend(
    _In_ QUIC_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_SEND_DATA* SendData,
    _In_ uint16_t IdealProcessor
    )
{
    UNREFERENCED_PARAMETER(IdealProcessor);
    QUIC_STATUS Status =
        QuicSocketSendInternal(
            Socket,
            LocalAddress,
            RemoteAddress,
            SendData,
            FALSE);
    if (Status == QUIC_STATUS_PENDING) {
        Status = QUIC_STATUS_SUCCESS;
    }
    return Status;
}


uint16_t
QuicSocketGetLocalMtu(
    _In_ QUIC_SOCKET* Socket
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);
    return Socket->Mtu;
}

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression)                              \
    ({                                                              \
        long int FailureRetryResult = 0;                            \
        do {                                                        \
            FailureRetryResult = (long int)(expression);            \
        } while ((FailureRetryResult == -1L) && (errno == EINTR));  \
        FailureRetryResult;                                         \
    })
#endif

void*
QuicDataPathWorkerThread(
    _In_ void* Context
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = (QUIC_DATAPATH_PROC_CONTEXT*)Context;
    QUIC_DBG_ASSERT(ProcContext != NULL && ProcContext->Datapath != NULL);

    QuicTraceLogInfo(
        "[data][%p] Worker start",
        ProcContext);

    const size_t EpollEventCtMax = 16; // TODO: Experiment.
    struct epoll_event EpollEvents[EpollEventCtMax];

    while (!ProcContext->Datapath->Shutdown) {
        int ReadyEventCount =
            TEMP_FAILURE_RETRY(
                epoll_wait(
                    ProcContext->EpollFd,
                    EpollEvents,
                    EpollEventCtMax,
                    -1));

        QUIC_FRE_ASSERT(ReadyEventCount >= 0);
        for (int i = 0; i < ReadyEventCount; i++) {
            if (EpollEvents[i].data.ptr == NULL) {
                //
                //The processor context is shutting down and the worker thread
                //needs to clean up.
                //                                              
                QUIC_DBG_ASSERT(ProcContext->Datapath->Shutdown);
                break;
            }

            QuicSocketContextProcessEvents(
                EpollEvents[i].data.ptr,
                EpollEvents[i].events);
        }
    }

    QuicTraceLogInfo(
        "[data][%p] Worker stop",
        ProcContext);

    return 0;
}

uint32_t Get_SockCount(_In_ QUIC_DATAPATH* Datapath, int Mode)
{
	return (Mode == CLIENT) ? 1: Datapath->ProcCount;
}


void SetsockOpt(_In_ QUIC_SOCKET* Socket, uint32_t Count, int Level, int Optname, const void * Optval, socklen_t Optlen)
{
    for (uint32_t i = 0; i < Count; i++) {
		setsockopt(Socket->SocketContexts[i].SocketFd, Level, Optname, Optval, Optlen);
	}
}  

void GetsockOpt(_In_ QUIC_SOCKET* Socket, uint32_t Count, int Level, int Optname, void * Optval, socklen_t *Optlen)
{
    getsockopt(Socket->SocketContexts[0].SocketFd, Level, Optname, Optval, Optlen);
}

 
