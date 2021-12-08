#define ENABLE_QUIC_PRINTF
#include <msquichelper.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	QUIC_SOCKFD Context;
    char Addr[32];
	int  State = 0;
	uint8_t data[200];
	uint32_t Result = 0, z = 10000;	
	QUIC_BUFFER SendBuffer;

	struct sockaddr_in PeerAddr, LocalAddr;

	if (GetValue(argc, argv, "?") || GetValue(argc, argv, "help")) {
        printf("Usage:\n");
        printf(" tcpclient.exe [-target:<...>] [-port:<...>] \n");
        return 0;
    }

	const char* Target = "quic.westus.cloudapp.azure.com";
	uint16_t Port = 4433;
	
    TryGetValue(argc, argv, "target", &Target);
    TryGetValue(argc, argv, "port", &Port);
		
	QuicZeroMemory(&Context, sizeof(QUIC_SOCKFD));
	if (QUIC_FAILED(MsQuicOpen(&(Context.MsQuic))))
    {
        printf("MsQuicOpen failed\n");
        return -1;
    }
	const QUIC_API_TABLE* MsQuic = Context.MsQuic;
	CHANNEL_DATA* MChannel = (CHANNEL_DATA*)MsQuic->TcpSocket(PF_INET, SOCK_STREAM, 0, &Context);
	
	if (QUIC_FAILED(MsQuic->TcpConnect(MChannel, Target, Port)))
	{
		printf("Client Connect failed\n");
		State = -1;
		goto End;
	}
	
	while(z--) {	
		for(int j = 0; j<100; j++)
		{
			data[j] = j;
		}

		SendBuffer.Length = sizeof(uint8_t)*100;
		SendBuffer.Buffer = data;			
		if (QUIC_FAILED(MsQuic->TcpSend(MChannel, &SendBuffer)))
		{
			printf("Client Send failed\n");
			State = -1;
			goto End;
		}
		QuicZeroMemory(data, sizeof(data));

		Result = MsQuic->TcpRecv(MChannel, data, sizeof(uint8_t)*200, &State);
		if (!Result && State)
		{
			State = -1;
			goto End;
		}

		for (uint32_t i=0; i<Result; i++)
		{
			printf("Client:%u ", data[i]);
		}
	}
	printf("\n");

End:	
	MsQuic->TcpClose(MChannel);
	return State;
}
 
