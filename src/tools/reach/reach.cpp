/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <time.h>
#include <stdio.h>

#include <vector>
#include <map>
#include <mutex>
#include <algorithm>

#include <quic_datapath.h>
#include <msquichelper.h>

uint16_t Port = 443;
const char* ServerName = "localhost";
const char* ServerIp = nullptr;
QUIC_ADDR ServerAddress = {0};

std::vector<const char*> ALPNs({ "h3", "h3-29", "hq-interop", "hq-29", "smb" });

const char* InputAlpn = nullptr;
uint32_t InputVersion = 0;

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;

extern "C" void QuicTraceRundown(void) { }

struct ConnectionContext {
    bool GotConnected;
    uint32_t QuicVersion;
    QUIC_EVENT Complete;
};

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ConnectionHandler(
    _In_ HQUIC Connection,
    _In_opt_ void* _Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
	uint32_t Size = 0;
    auto Context = (ConnectionContext*)_Context;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        Context->GotConnected = true;
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        Size = sizeof(Context->QuicVersion);
        MsQuic->GetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_QUIC_VERSION, &Size, &Context->QuicVersion);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->ConnectionClose(Connection);
        QuicEventSet(Context->Complete);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        return QUIC_STATUS_NOT_SUPPORTED;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_THREAD_CALLBACK(TestReachability, _Alpn)
{
    QUIC_BUFFER Alpn;
    Alpn.Buffer = (uint8_t*)_Alpn;
    Alpn.Length = (uint32_t)strlen((char*)_Alpn);

    QUIC_SETTINGS Settings{0};
    Settings.PeerUnidiStreamCount = 100;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;
    Settings.IdleTimeoutMs = 10 * 1000;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    if (InputVersion) {
        Settings.IsSet.DesiredVersionsList = TRUE;
        Settings.DesiredVersionsList = &InputVersion;
        Settings.DesiredVersionsListLength = 1;
    }

    HQUIC Configuration = nullptr;
    if (QUIC_FAILED(MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), nullptr, &Configuration))) {
        printf("ConfigurationOpen failed.\n");
        exit(1);
    }

    QUIC_CREDENTIAL_CONFIG CredConfig;
    QuicZeroMemory(&CredConfig, sizeof(CredConfig));
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT; // TODO - Disable certificate validation?

    if (QUIC_FAILED(MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationOpen failed.\n");
        exit(1);
    }

    ConnectionContext Context = { false };
    QuicEventInitialize(&Context.Complete, TRUE, FALSE);

    HQUIC Connection = nullptr;
    if (QUIC_FAILED(MsQuic->ConnectionOpen(Registration, ConnectionHandler, &Context, &Connection))) {
        printf("ConnectionOpen failed.\n");
        exit(1);
    }

    if (QUIC_FAILED(MsQuic->SetParam(Connection, QUIC_PARAM_LEVEL_CONNECTION, QUIC_PARAM_CONN_REMOTE_ADDRESS, sizeof(ServerAddress), &ServerAddress))) {
        printf("SetParam QUIC_PARAM_CONN_REMOTE_ADDRESS failed.\n");
        exit(1);
    }

    if (QUIC_FAILED(MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, ServerName, Port))) {
        printf("ConnectionStart failed.\n");
        exit(1);
    }

    MsQuic->ConfigurationClose(Configuration);
    QuicEventWaitForever(Context.Complete);
    QuicEventUninitialize(Context.Complete);

    if (Context.GotConnected) {
        printf("  %6s    reachable\n", (char*)_Alpn);
    } else {
        printf("  %6s  unreachable\n", (char*)_Alpn);
    }

    QUIC_THREAD_RETURN(0);
}

int
QUIC_MAIN_EXPORT
main(int argc, char **argv)
{
    if (argc > 1 &&
        (
            !strcmp(argv[1], "?") ||
            !strcmp(argv[1], "-?") ||
            !strcmp(argv[1], "--?") ||
            !strcmp(argv[1], "/?") ||
            !strcmp(argv[1], "help")
        )) {
        printf("Usage: quicreach.exe [-server:<name>] [-ip:<ip>] [-port:<number>] [-alpn:<alpn>] [-version:<quic_version>]\n");
        exit(1);
    }

    TryGetValue(argc, argv, "server", &ServerName);
    TryGetValue(argc, argv, "ip", &ServerIp);
    TryGetValue(argc, argv, "port", &Port);
    TryGetValue(argc, argv, "alpn", &InputAlpn);
    TryGetValue(argc, argv, "version", &InputVersion);


    QuicPlatformSystemLoad();
    QuicPlatformInitialize();

    if (ServerIp == nullptr) {
        QUIC_DATAPATH* Datapath = nullptr;
        if (QUIC_FAILED(
            QuicDataPathInitialize(
                0,
                NULL,
                NULL,
                &Datapath))) {
            printf("QuicDataPathInitialize failed.\n");
            exit(1);
        }
        if (QUIC_FAILED(
            QuicDataPathResolveAddress(
                Datapath,
                ServerName,
                &ServerAddress))) {
            printf("Failed to resolve IP address of '%s'.\n", ServerName);
            exit(1);
        }
        QuicDataPathUninitialize(Datapath);
    } else {
        if (!QuicAddrFromString(ServerIp, Port, &ServerAddress)) {
            printf("QuicAddrFromString failed.\n");
            exit(1);
        }
    }

    if (QUIC_FAILED(MsQuicOpen(&MsQuic))) {
        printf("MsQuicOpen failed.\n");
        exit(1);
    }

    const QUIC_REGISTRATION_CONFIG RegConfig = { "reach", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed.\n");
        exit(1);
    }

    printf("\n%s:%hu:\n\n", ServerName, Port);

    std::vector<QUIC_THREAD> Threads;
    QUIC_THREAD_CONFIG Config = { 0, 0, "reach_worker", TestReachability, nullptr };

    if (InputAlpn != nullptr) {
        Config.Context = (void*)InputAlpn;
        QUIC_THREAD Thread;
        if (QUIC_FAILED(QuicThreadCreate(&Config, &Thread))) {
            printf("QuicThreadCreate failed.\n");
            exit(1);
        }
        Threads.push_back(Thread);
    } else {
        for (auto ALPN : ALPNs) {
            Config.Context = (void*)ALPN;
            QUIC_THREAD Thread;
            if (QUIC_FAILED(QuicThreadCreate(&Config, &Thread))) {
                printf("QuicThreadCreate failed.\n");
                exit(1);
            }
            Threads.push_back(Thread);
        }
    }

    for (auto Thread : Threads) {
        QuicThreadWait(&Thread);
        QuicThreadDelete(&Thread);
    }

    MsQuic->RegistrationClose(Registration);

    MsQuicClose(MsQuic);

    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return 0;
}
