#define ENABLE_QUIC_PRINTF
#include <msquichelper.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	QUIC_SOCKFD Context;
    char Addr[32];
	int  State = 0;
	uint8_t data[200];
	uint32_t Result = 0;	
	QUIC_BUFFER SendBuffer;
	const QUIC_BUFFER Alpn = { sizeof("ip") - 1, (uint8_t*)"ip" };
	struct sockaddr_in PeerAddr, LocalAddr;

	if (GetValue(argc, argv, "?") || GetValue(argc, argv, "help")) {
        printf("Usage:\n");
        printf(" tcpclient.exe [-target:<...>] [-port:<...>] \n");
        return 0;
    }

	const char* Target = "quic.westus.cloudapp.azure.com";
	const char* Port = "4433";
	
    TryGetValue(argc, argv, "target", &Target);
    TryGetValue(argc, argv, "port", &Port);
		
	memset(&Context, 0, sizeof(QUIC_SOCKFD));
	if (QUIC_FAILED(MsQuicOpen(&(Context.MsQuic))))
    {
        printf("MsQuicOpen failed\n");
        return -1;
    }
	
	const QUIC_API_TABLE* MsQuic = Context.MsQuic;
	CHANNEL_DATA* MainChannel = (CHANNEL_DATA*)MsQuic->TcpSocket(PF_INET, SOCK_STREAM, 0, &Context);

	if (QUIC_FAILED(MsQuic->TcpConnect(MainChannel, Target, atoi(Port))))
	{
		printf("Client Connect failed\n");
		State = -1;
		goto End;
	}

	if (MsQuic->MsQuicGetPeerName(MainChannel, (struct sockaddr*)&PeerAddr, NULL) < 0)
	{
		printf("Call MsQuicGetPeerName failed\n");
		goto End;
	}

    if (MsQuic->MsQuicGetSockName(MainChannel, (struct sockaddr*)&LocalAddr, NULL) < 0)
    {
       	printf("Call MsQuicGetPeerName failed\n");
        goto End;
    }
		
	for(int j = 0; j<100; j++)
	{
		data[j] = j;
	}

	SendBuffer.Length = sizeof(uint8_t)*100;
	SendBuffer.Buffer = data;			
	if (QUIC_FAILED(MsQuic->TcpSend(MainChannel, &SendBuffer)))
	{
		printf("Client Send failed\n");
		State = -1;
		goto End;
	}
		
	memset(data, 0, sizeof(data));	
	Result = MsQuic->TcpRecv(MainChannel, data, sizeof(uint8_t)*200, &State);
	if (!Result && State)
	{
		State = -1;
		goto End;
	}

	for (uint32_t i=0; i<Result; i++)
	{
		printf("Client:%u ", data[i]);
	}
	printf("\n");

End:	
	MsQuic->TcpClose(MainChannel);
	return State;
}
 
