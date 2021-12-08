/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath User Mode Unit test

--*/

#include "main.h"
#include "quic_datapath.h"

#include "msquic.h"

const uint32_t ExpectedDataSize = 1 * 1024;
char* ExpectedData;

//
// Helper class for managing the memory of a IP address.
//
struct QuicAddr
{
    QUIC_ADDR SockAddr;

    uint16_t Port() {
        if (QuicAddrGetFamily(&SockAddr) == QUIC_ADDRESS_FAMILY_INET) {
            return SockAddr.Ipv4.sin_port;
        } else {
            return SockAddr.Ipv6.sin6_port;
        }
    }

    #undef SetPort
    void SetPort(uint16_t port) {
        if (QuicAddrGetFamily(&SockAddr) == QUIC_ADDRESS_FAMILY_INET) {
            SockAddr.Ipv4.sin_port = port;
        } else {
            SockAddr.Ipv6.sin6_port = port;
        }
    }

    QuicAddr() {
        QuicZeroMemory(this, sizeof(*this));
    }

    void Resolve(QUIC_ADDRESS_FAMILY af, const char* hostname) {
        UNREFERENCED_PARAMETER(af);
        QUIC_DATAPATH* Datapath = nullptr;
        if (QUIC_FAILED(
            QuicDataPathInitialize(
                0,
                NULL,
                NULL,
                &Datapath))) {
            GTEST_FATAL_FAILURE_(" QuicDataPathInitialize failed.");
        }
        if (QUIC_FAILED(
            QuicDataPathResolveAddress(
                Datapath,
                hostname,
                &SockAddr))) {
            GTEST_FATAL_FAILURE_("Failed to resolve IP address.");
        }
        QuicDataPathUninitialize(Datapath);
    }
};


struct UdpRecvContext {
    QUIC_ADDR DestinationAddress;
    QUIC_EVENT ClientCompletion;
    QUIC_ECN_TYPE EcnType {QUIC_ECN_NON_ECT};
    UdpRecvContext() {
        QuicEventInitialize(&ClientCompletion, FALSE, FALSE);
    }
    ~UdpRecvContext() {
        QuicEventUninitialize(ClientCompletion);
    }
};

struct TcpClientContext {
    bool Connected : 1;
    bool Disconnected : 1;
    bool Received : 1;
    QUIC_EVENT ConnectEvent;
    QUIC_EVENT DisconnectEvent;
    QUIC_EVENT ReceiveEvent;
    TcpClientContext() : Connected(false), Disconnected(false), Received(false) {
        QuicEventInitialize(&ConnectEvent, FALSE, FALSE);
        QuicEventInitialize(&DisconnectEvent, FALSE, FALSE);
        QuicEventInitialize(&ReceiveEvent, FALSE, FALSE);
    }
    ~TcpClientContext() {
        QuicEventUninitialize(ConnectEvent);
        QuicEventUninitialize(DisconnectEvent);
        QuicEventUninitialize(ReceiveEvent);
    }
};

struct TcpListenerContext {
    QUIC_SOCKET* Server;
    TcpClientContext ServerContext;
    bool Accepted : 1;
    QUIC_EVENT AcceptEvent;
    TcpListenerContext() : Server(nullptr), Accepted(false) {
        QuicEventInitialize(&AcceptEvent, FALSE, FALSE);
    }
    ~TcpListenerContext() {
        DeleteSocket();
        QuicEventUninitialize(AcceptEvent);
    }
    void DeleteSocket() {
        if (Server) {
            QuicSocketDelete(Server);
            Server = nullptr;
        }
    }
};


struct DataPathTest : public ::testing::TestWithParam<int32_t>
{
protected:
    static volatile uint16_t NextPort;
    static QuicAddr LocalIPv4;
    static QuicAddr LocalIPv6;

    //
    // Helper to get a new port to bind to.
    //
    uint16_t
    GetNextPort()
    {
        return QuicNetByteSwapShort((uint16_t)InterlockedIncrement16((volatile short*)&NextPort));
    }

    //
    // Helper to return a new local IPv4 address and port to use.
    //
    QuicAddr
    GetNewLocalIPv4(bool randomPort = true)
    {
        QuicAddr ipv4Copy = LocalIPv4;
        if (randomPort) { ipv4Copy.SockAddr.Ipv4.sin_port = GetNextPort(); }
        else { ipv4Copy.SockAddr.Ipv4.sin_port = 0; }
        return ipv4Copy;
    }

    //
    // Helper to return a new local IPv4 address and port to use.
    //
    QuicAddr
    GetNewLocalIPv6(bool randomPort = true)
    {
        QuicAddr ipv6Copy = LocalIPv6;
        if (randomPort) { ipv6Copy.SockAddr.Ipv6.sin6_port = GetNextPort(); }
        else { ipv6Copy.SockAddr.Ipv6.sin6_port = 0; }
        return ipv6Copy;
    }

    //
    // Helper to return a new local IPv4 or IPv6 address based on the test data.
    //
    QuicAddr
    GetNewLocalAddr(bool randomPort = true)
    {
        int addressFamily = GetParam();

        if (addressFamily == 4) {
            return GetNewLocalIPv4(randomPort);
        } else if (addressFamily == 6) {
            return GetNewLocalIPv6(randomPort);
        } else {
            GTEST_NONFATAL_FAILURE_("Malconfigured test data; This should never happen!!");
            return QuicAddr();
        }
    }

    static void SetUpTestSuite()
    {
        //
        // Initialize a semi-random base port number.
        //
        NextPort = 50000 + (QuicCurThreadID() % 10000) + (rand() % 5000);

        LocalIPv4.Resolve(QUIC_ADDRESS_FAMILY_INET, "localhost");
        LocalIPv6.Resolve(QUIC_ADDRESS_FAMILY_INET6, "localhost");

        ExpectedData = (char*)QUIC_ALLOC_NONPAGED(ExpectedDataSize);
        ASSERT_NE(ExpectedData, nullptr);
    }

    static void TearDownTestSuite()
    {
        QUIC_FREE(ExpectedData);
    }

    static void
    EmptyReceiveCallback(
        _In_ QUIC_SOCKET* /* Binding */,
        _In_ void * /* RecvContext */,
        _In_ QUIC_RECV_DATA* /* RecvPacketChain */
        )
    {
    }

    static void
    EmptyUnreachableCallback(
        _In_ QUIC_SOCKET* /* Binding */,
        _In_ void * /* Context */,
        _In_ const QUIC_ADDR* /* RemoteAddress */
        )
    {
    }

    static void
    UdpDataRecvCallback(
        _In_ QUIC_SOCKET* Socket,
        _In_ void * Context,
        _In_ QUIC_RECV_DATA* RecvDataChain
        )
    {
        UdpRecvContext* RecvContext = (UdpRecvContext*)Context;
        ASSERT_NE(nullptr, RecvContext);

        QUIC_RECV_DATA* RecvData = RecvDataChain;

        while (RecvData != NULL) {
            ASSERT_EQ(RecvData->BufferLength, ExpectedDataSize);
            ASSERT_EQ(0, memcmp(RecvData->Buffer, ExpectedData, ExpectedDataSize));

            if (RecvData->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->DestinationAddress.Ipv4.sin_port) {

                ASSERT_EQ((QUIC_ECN_TYPE)RecvData->TypeOfService, RecvContext->EcnType);

                auto ServerSendData  = QuicSendDataAlloc(Socket, RecvContext->EcnType, 0);
                ASSERT_NE(nullptr, ServerSendData);

                auto ServerBuffer = QuicSendDataAllocBuffer(ServerSendData, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerBuffer);

                memcpy(ServerBuffer->Buffer, RecvData->Buffer, RecvData->BufferLength);

                VERIFY_QUIC_SUCCESS(
                    QuicSocketSend(
                        Socket,
                        &RecvData->Tuple->LocalAddress,
                        &RecvData->Tuple->RemoteAddress,
                        ServerSendData,
						0));

            } else if (RecvData->Tuple->RemoteAddress.Ipv4.sin_port == RecvContext->DestinationAddress.Ipv4.sin_port){
				QuicEventSet(RecvContext->ClientCompletion);

			} else {
                GTEST_NONFATAL_FAILURE_("Received on unexpected address!");
            }

            RecvData = RecvData->Next;
        }
		QuicRecvDataReturn(RecvDataChain);
    }

    static void
    EmptyAcceptCallback(
        _In_ QUIC_SOCKET* /* ListenerSocket */,
        _In_ void* /* ListenerContext */,
        _In_ QUIC_SOCKET* /* ClientSocket */,
        _Out_ void** /* ClientContext */
        )
    {
    }

    static void
    EmptyConnectCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ BOOLEAN /* Connected */
        )
    {
    }

    static void
    TcpAcceptCallback(
        _In_ QUIC_SOCKET* /* ListenerSocket */,
        _In_ void* Context,
        _In_ QUIC_SOCKET* ClientSocket,
        _Out_ void** ClientContext
        )
    {
        TcpListenerContext* ListenerContext = (TcpListenerContext*)Context;
        ListenerContext->Server = ClientSocket;
        *ClientContext = &ListenerContext->ServerContext;
        ListenerContext->Accepted = true;
        QuicEventSet(ListenerContext->AcceptEvent);
    }

    static void
    TcpConnectCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* Context,
        _In_ BOOLEAN Connected
        )
    {
        TcpClientContext* ClientContext = (TcpClientContext*)Context;
        if (Connected) {
            ClientContext->Connected = true;
            QuicEventSet(ClientContext->ConnectEvent);
        } else {
            ClientContext->Disconnected = true;
            QuicEventSet(ClientContext->DisconnectEvent);
        }
    }

    static void
    TcpDataRecvCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* Context,
        _In_ QUIC_RECV_DATA* RecvDataChain
        )
    {
        if (Context) {
            TcpClientContext* ClientContext = (TcpClientContext*)Context;
            ClientContext->Received = true;
            QuicEventSet(ClientContext->ReceiveEvent);
        }
        QuicRecvDataReturn(RecvDataChain);
    }

    static void
    TcpEmptySendCompleteCallback(
        _In_ QUIC_SOCKET* /* Socket */,
        _In_ void* /* Context */,
        _In_ QUIC_STATUS /* Status */,
        _In_ uint32_t /* ByteCount */
        )
    {
    }

    const QUIC_UDP_DATAPATH_CALLBACKS EmptyUdpCallbacks = {
        EmptyReceiveCallback,
        EmptyUnreachableCallback,
    };

    const QUIC_UDP_DATAPATH_CALLBACKS UdpRecvCallbacks = {
        UdpDataRecvCallback,
        EmptyUnreachableCallback,
    };

    const QUIC_TCP_DATAPATH_CALLBACKS EmptyTcpCallbacks = {
        EmptyAcceptCallback,
        EmptyConnectCallback,
        EmptyReceiveCallback,
        TcpEmptySendCompleteCallback
    };

    const QUIC_TCP_DATAPATH_CALLBACKS TcpRecvCallbacks = {
        TcpAcceptCallback,
        TcpConnectCallback,
        TcpDataRecvCallback,
        TcpEmptySendCompleteCallback
    };
};

volatile uint16_t DataPathTest::NextPort;
QuicAddr DataPathTest::LocalIPv4;
QuicAddr DataPathTest::LocalIPv6;

struct QuicDataPath {
    QUIC_DATAPATH* Datapath {nullptr};
    QUIC_STATUS InitStatus;
    QuicDataPath(
        _In_opt_ const QUIC_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
        _In_opt_ const QUIC_TCP_DATAPATH_CALLBACKS* TcpCallbacks = nullptr,
        _In_ uint32_t ClientRecvContextLength = 0
        ) noexcept
    {
        InitStatus =
            QuicDataPathInitialize(
                ClientRecvContextLength,
                UdpCallbacks,
                TcpCallbacks,
                &Datapath);
    }
    ~QuicDataPath() noexcept {
        if (Datapath) {
            QuicDataPathUninitialize(Datapath);
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    QuicDataPath(QuicDataPath& other) = delete;
    QuicDataPath operator=(QuicDataPath& Other) = delete;
    operator QUIC_DATAPATH* () const noexcept { return Datapath; }
    uint32_t GetSupportedFeatures() const noexcept { return QuicDataPathGetSupportedFeatures(Datapath); }
};


struct QuicSocket {
    QUIC_SOCKET* Socket {nullptr};
    QUIC_STATUS InitStatus {QUIC_STATUS_INVALID_STATE};
    QuicSocket() { }
    QuicSocket(
        _In_ QuicDataPath& Datapath,
        _In_opt_ const QUIC_ADDR* LocalAddress = nullptr,
        _In_opt_ const QUIC_ADDR* RemoteAddress = nullptr,
        _In_opt_ void* CallbackContext = nullptr,
        _In_ uint32_t InternalFlags = 0
        ) noexcept // UDP
    {
        CreateUdp(
            Datapath,
            LocalAddress,
            RemoteAddress,
            CallbackContext,
            InternalFlags);
    }
    ~QuicSocket() noexcept {
        if (Socket) {
            QuicSocketDelete(Socket);
        }
    }
    QUIC_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return QUIC_SUCCEEDED(InitStatus); }
    QuicSocket(QuicSocket& other) = delete;
    QuicSocket operator=(QuicSocket& Other) = delete;
    operator QUIC_SOCKET* () const noexcept { return Socket; }
    void CreateUdp(
        _In_ QuicDataPath& Datapath,
        _In_opt_ const QUIC_ADDR* LocalAddress = nullptr,
        _In_opt_ const QUIC_ADDR* RemoteAddress = nullptr,
        _In_opt_ void* CallbackContext = nullptr,
        _In_ uint32_t InternalFlags = 0
        ) noexcept
    {
        QUIC_UDP_CONFIG UdpConfig = {0};
        UdpConfig.LocalAddress = LocalAddress;
        UdpConfig.RemoteAddress = RemoteAddress;
        UdpConfig.Flags = InternalFlags;
        UdpConfig.InterfaceIndex = 0;
        UdpConfig.CallbackContext = CallbackContext;
        InitStatus =
            QuicSocketCreateUdp(
                Datapath,
                &UdpConfig,
                &Socket);
#ifdef _WIN32
        if (InitStatus == HRESULT_FROM_WIN32(WSAEACCES)) {
            InitStatus = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(LocalAddress->Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    void CreateTcp(
        _In_ QuicDataPath& Datapath,
        _In_opt_ const QUIC_ADDR* LocalAddress,
        _In_ const QUIC_ADDR* RemoteAddress,
        _In_opt_ void* CallbackContext = nullptr
        ) noexcept
    {
        InitStatus =
            QuicSocketCreateTcp(
                Datapath,
                LocalAddress,
                RemoteAddress,
                CallbackContext,
                &Socket);
    }
    void CreateTcpListener(
        _In_ QuicDataPath& Datapath,
        _In_opt_ const QUIC_ADDR* LocalAddress = nullptr,
        _In_opt_ void* CallbackContext = nullptr
        ) noexcept
    {
        InitStatus =
            QuicSocketCreateTcpListener(
                Datapath,
                LocalAddress,
                CallbackContext,
                &Socket);
#ifdef _WIN32
        if (InitStatus == HRESULT_FROM_WIN32(WSAEACCES)) {
            InitStatus = QUIC_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(LocalAddress->Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    QUIC_ADDR GetLocalAddress() const noexcept {
        QUIC_ADDR Addr;
        QuicSocketGetLocalAddress(Socket, &Addr);
        return Addr;
    }
    QUIC_ADDR GetRemoteAddress() const noexcept {
        QUIC_ADDR Addr;
        QuicSocketGetRemoteAddress(Socket, &Addr);
        return Addr;
    }
    QUIC_STATUS
    Send(
        _In_ const QUIC_ADDR& LocalAddress,
        _In_ const QUIC_ADDR& RemoteAddress,
        _In_ QUIC_SEND_DATA* SendData,
        _In_ uint16_t PartitionId = 0
        ) const noexcept
    {
        return
            QuicSocketSend(
                Socket,
                &LocalAddress,
                &RemoteAddress,
                SendData,
                PartitionId);
    }
    QUIC_STATUS
    Send(
        _In_ const QUIC_ADDR& RemoteAddress,
        _In_ QUIC_SEND_DATA* SendData,
        _In_ uint16_t PartitionId = 0
        ) const noexcept
    {
        return Send(GetLocalAddress(), RemoteAddress, SendData, PartitionId);
    }
    QUIC_STATUS
    Send(
        _In_ QUIC_SEND_DATA* SendData,
        _In_ uint16_t PartitionId = 0
        ) const noexcept
    {
        return Send(GetLocalAddress(), GetRemoteAddress(), SendData, PartitionId);
    }
};


TEST_F(DataPathTest, Initialize)
{
	{
    	QuicDataPath Datapath(nullptr);
	    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }

    {
        QuicDataPath Datapath(&EmptyUdpCallbacks);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }

    {
        QuicDataPath Datapath(nullptr, &EmptyTcpCallbacks);
        VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
        ASSERT_NE(nullptr, Datapath.Datapath);
    }

}


TEST_F(DataPathTest, InitializeInvalid)
{
    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER, QuicDataPathInitialize(0, nullptr, nullptr, nullptr));
	{

 		const QUIC_UDP_DATAPATH_CALLBACKS InvalidUdpCallbacks = { nullptr, EmptyUnreachableCallback };
		QuicDataPath Datapath(&InvalidUdpCallbacks);

        ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER, Datapath.GetInitStatus());
        ASSERT_EQ(nullptr, Datapath.Datapath);
	}

    {
        const QUIC_UDP_DATAPATH_CALLBACKS InvalidUdpCallbacks = { EmptyReceiveCallback, nullptr };
        QuicDataPath Datapath(&InvalidUdpCallbacks);
        ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER, Datapath.GetInitStatus());
        ASSERT_EQ(nullptr, Datapath.Datapath);
    }
}

TEST_F(DataPathTest, UdpBind)
{

    QuicDataPath Datapath(&EmptyUdpCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());

    ASSERT_NE(nullptr, Datapath.Datapath);

    QuicSocket Socket(Datapath);
    VERIFY_QUIC_SUCCESS(Socket.GetInitStatus());

    ASSERT_NE(nullptr, Socket.Socket);
    ASSERT_NE(Socket.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

}



TEST_F(DataPathTest, UdpRebind)
{
    QuicDataPath Datapath(&EmptyUdpCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());

    ASSERT_NE(nullptr, Datapath.Datapath);

    QuicSocket Socket1(Datapath);
    VERIFY_QUIC_SUCCESS(Socket1.GetInitStatus());

    ASSERT_NE(nullptr, Socket1.Socket);
    ASSERT_NE(Socket1.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    QuicSocket Socket2(Datapath);
    VERIFY_QUIC_SUCCESS(Socket2.GetInitStatus());
    ASSERT_NE(nullptr, Socket2.Socket);
    ASSERT_NE(Socket2.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

}


TEST_P(DataPathTest, UdpData)
{
    UdpRecvContext RecvContext;
    QuicDataPath Datapath(&UdpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    auto serverAddress = GetNewLocalAddr();
    QuicSocket Server(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    while (Server.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server.CreateUdp(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server.GetInitStatus());
    ASSERT_NE(nullptr, Server.Socket);
    RecvContext.DestinationAddress = Server.GetLocalAddress();
    ASSERT_NE(RecvContext.DestinationAddress.Ipv4.sin_port, (uint16_t)0);

    QuicSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);

    auto ClientSendData = QuicSendDataAlloc(Client, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendData);
    auto ClientBuffer = QuicSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    VERIFY_QUIC_SUCCESS(Client.Send(ClientSendData));
    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
}


TEST_P(DataPathTest, UdpDataRebind)
{
    UdpRecvContext RecvContext;
    QuicDataPath Datapath(&UdpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    auto serverAddress = GetNewLocalAddr();
    QuicSocket Server(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    while (Server.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server.CreateUdp(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    }

    VERIFY_QUIC_SUCCESS(Server.GetInitStatus());
    ASSERT_NE(nullptr, Server.Socket);
    RecvContext.DestinationAddress = Server.GetLocalAddress();
    ASSERT_NE(RecvContext.DestinationAddress.Ipv4.sin_port, (uint16_t)0);

    {
        QuicSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
        VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
        ASSERT_NE(nullptr, Client.Socket);

        auto ClientSendData = QuicSendDataAlloc(Client, QUIC_ECN_NON_ECT, 0);
        ASSERT_NE(nullptr, ClientSendData);
        auto ClientBuffer = QuicSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
        ASSERT_NE(nullptr, ClientBuffer);
        memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

        VERIFY_QUIC_SUCCESS(Client.Send(ClientSendData));
        ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
        QuicEventReset(RecvContext.ClientCompletion);
    }

    {
        QuicSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
        VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
        ASSERT_NE(nullptr, Client.Socket);

        auto ClientSendData = QuicSendDataAlloc(Client, QUIC_ECN_NON_ECT, 0);
        ASSERT_NE(nullptr, ClientSendData);
        auto ClientBuffer = QuicSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
        ASSERT_NE(nullptr, ClientBuffer);
        memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

        VERIFY_QUIC_SUCCESS(Client.Send(ClientSendData));
        ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
    }
}

TEST_P(DataPathTest, UdpDataECT0)
{
    UdpRecvContext RecvContext;
    RecvContext.EcnType = QUIC_ECN_ECT_0;
    QuicDataPath Datapath(&UdpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    auto serverAddress = GetNewLocalAddr();
    QuicSocket Server(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    while (Server.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server.CreateUdp(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server.GetInitStatus());
    ASSERT_NE(nullptr, Server.Socket);
    RecvContext.DestinationAddress = Server.GetLocalAddress();
    ASSERT_NE(RecvContext.DestinationAddress.Ipv4.sin_port, (uint16_t)0);

    QuicSocket Client(Datapath, nullptr, &RecvContext.DestinationAddress, &RecvContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);

    auto ClientSendData = QuicSendDataAlloc(Client, QUIC_ECN_ECT_0, 0);
    ASSERT_NE(nullptr, ClientSendData);
    auto ClientBuffer = QuicSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    VERIFY_QUIC_SUCCESS(Client.Send(ClientSendData));
    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
}

TEST_P(DataPathTest, UdpShareClientSocket)
{
    UdpRecvContext RecvContext;
    QuicDataPath Datapath(&UdpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);
    if (!(Datapath.GetSupportedFeatures() & QUIC_DATAPATH_FEATURE_LOCAL_PORT_SHARING)) {
        std::cout << "SKIP: Sharing Feature Unsupported" << std::endl;
        return;
    }

    auto serverAddress = GetNewLocalAddr();
    QuicSocket Server1(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    while (Server1.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server1.CreateUdp(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server1.GetInitStatus());

    serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
    QuicSocket Server2(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    while (Server2.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Server2.CreateUdp(Datapath, &serverAddress.SockAddr, nullptr, &RecvContext);
    }
    VERIFY_QUIC_SUCCESS(Server2.GetInitStatus());

    serverAddress.SockAddr = Server1.GetLocalAddress();
    QuicSocket Client1(Datapath, nullptr, &serverAddress.SockAddr, &RecvContext, QUIC_SOCKET_FLAG_SHARE);
    VERIFY_QUIC_SUCCESS(Client1.GetInitStatus());

    auto clientAddress = Client1.GetLocalAddress();
    serverAddress.SockAddr = Server2.GetLocalAddress();
    QuicSocket Client2(Datapath, &clientAddress, &serverAddress.SockAddr, &RecvContext, QUIC_SOCKET_FLAG_SHARE);
    VERIFY_QUIC_SUCCESS(Client2.GetInitStatus());

    auto ClientSendData = QuicSendDataAlloc(Client1, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendData);
    auto ClientBuffer = QuicSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    RecvContext.DestinationAddress = Server1.GetLocalAddress();
    VERIFY_QUIC_SUCCESS(Client1.Send(ClientSendData));
    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
    QuicEventReset(RecvContext.ClientCompletion);

    ClientSendData = QuicSendDataAlloc(Client2, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendData);
    ClientBuffer = QuicSendDataAllocBuffer(ClientSendData, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientBuffer);
    memcpy(ClientBuffer->Buffer, ExpectedData, ExpectedDataSize);

    RecvContext.DestinationAddress = Server2.GetLocalAddress();
    VERIFY_QUIC_SUCCESS(Client2.Send(ClientSendData));
    ASSERT_TRUE(QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));
    QuicEventReset(RecvContext.ClientCompletion);
}

#if WIN32
TEST_F(DataPathTest, TcpListener)
{
    QuicDataPath Datapath(nullptr, &EmptyTcpCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    QuicSocket Listener; Listener.CreateTcpListener(Datapath, nullptr, &ListenerContext);
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    ASSERT_NE(Listener.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);
}

TEST_P(DataPathTest, TcpConnect)
{
    QuicDataPath Datapath(nullptr, &TcpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    QuicSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    TcpClientContext ClientContext;
    QuicSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);
    ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    ASSERT_TRUE(QuicEventWaitWithTimeout(ClientContext.ConnectEvent, 100));
    ASSERT_TRUE(QuicEventWaitWithTimeout(ListenerContext.AcceptEvent, 100));
    ASSERT_NE(nullptr, ListenerContext.Server);

    ListenerContext.DeleteSocket();

    ASSERT_TRUE(QuicEventWaitWithTimeout(ClientContext.DisconnectEvent, 100));
}

TEST_P(DataPathTest, TcpDisconnect)
{
    QuicDataPath Datapath(nullptr, &TcpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    QuicSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    {
        TcpClientContext ClientContext;
        QuicSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
        VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
        ASSERT_NE(nullptr, Client.Socket);
        ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

        ASSERT_TRUE(QuicEventWaitWithTimeout(ClientContext.ConnectEvent, 100));
        ASSERT_TRUE(QuicEventWaitWithTimeout(ListenerContext.AcceptEvent, 100));
        ASSERT_NE(nullptr, ListenerContext.Server);
    }

    ASSERT_TRUE(QuicEventWaitWithTimeout(ListenerContext.ServerContext.DisconnectEvent, 100));
}

TEST_P(DataPathTest, TcpDataClient)
{
    QuicDataPath Datapath(nullptr, &TcpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    QuicSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    TcpClientContext ClientContext;
    QuicSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);
    ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    ASSERT_TRUE(QuicEventWaitWithTimeout(ClientContext.ConnectEvent, 100));
    ASSERT_TRUE(QuicEventWaitWithTimeout(ListenerContext.AcceptEvent, 100));
    ASSERT_NE(nullptr, ListenerContext.Server);

    auto SendData = QuicSendDataAlloc(Client, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, SendData);
    auto SendBuffer = QuicSendDataAllocBuffer(SendData, ExpectedDataSize);
    ASSERT_NE(nullptr, SendBuffer);
    memcpy(SendBuffer->Buffer, ExpectedData, ExpectedDataSize);

    VERIFY_QUIC_SUCCESS(Client.Send(SendData));
    ASSERT_TRUE(QuicEventWaitWithTimeout(ListenerContext.ServerContext.ReceiveEvent, 100));
}

TEST_P(DataPathTest, TcpDataServer)
{
    QuicDataPath Datapath(nullptr, &TcpRecvCallbacks);
    VERIFY_QUIC_SUCCESS(Datapath.GetInitStatus());
    ASSERT_NE(nullptr, Datapath.Datapath);

    TcpListenerContext ListenerContext;
    auto serverAddress = GetNewLocalAddr();
    QuicSocket Listener; Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    while (Listener.GetInitStatus() == QUIC_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Listener.CreateTcpListener(Datapath, &serverAddress.SockAddr, &ListenerContext);
    }
    VERIFY_QUIC_SUCCESS(Listener.GetInitStatus());
    ASSERT_NE(nullptr, Listener.Socket);
    serverAddress.SockAddr = Listener.GetLocalAddress();
    ASSERT_NE(serverAddress.SockAddr.Ipv4.sin_port, (uint16_t)0);

    TcpClientContext ClientContext;
    QuicSocket Client; Client.CreateTcp(Datapath, nullptr, &serverAddress.SockAddr, &ClientContext);
    VERIFY_QUIC_SUCCESS(Client.GetInitStatus());
    ASSERT_NE(nullptr, Client.Socket);
    ASSERT_NE(Client.GetLocalAddress().Ipv4.sin_port, (uint16_t)0);

    ASSERT_TRUE(QuicEventWaitWithTimeout(ClientContext.ConnectEvent, 100));
    ASSERT_TRUE(QuicEventWaitWithTimeout(ListenerContext.AcceptEvent, 100));
    ASSERT_NE(nullptr, ListenerContext.Server);

    auto SendData = QuicSendDataAlloc(ListenerContext.Server, QUIC_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, SendData);
    auto SendBuffer = QuicSendDataAllocBuffer(SendData, ExpectedDataSize);
    ASSERT_NE(nullptr, SendBuffer);
    memcpy(SendBuffer->Buffer, ExpectedData, ExpectedDataSize);

    QUIC_ADDR ServerAddress = Listener.GetLocalAddress();
    QUIC_ADDR ClientAddress = Client.GetLocalAddress();

    VERIFY_QUIC_SUCCESS(
        QuicSocketSend(
            ListenerContext.Server,
            &ServerAddress,
            &ClientAddress,
            SendData, 0));
    ASSERT_TRUE(QuicEventWaitWithTimeout(ClientContext.ReceiveEvent, 100));
}
#endif // WIN32

INSTANTIATE_TEST_SUITE_P(DataPathTest, DataPathTest, ::testing::Values(4, 6), testing::PrintToStringParamName());
