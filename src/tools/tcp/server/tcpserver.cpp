#include <quic_tls.h> 
#include <msquichelper.h>
#include "msquic.h"

#define MAX_EVENTS 128

typedef struct Recv_Message
{
	QUIC_SOCKFD *Context;
	CHANNEL_DATA *Channel;
}Recv_Mess;

int main(int argc, char *argv[])
{
    QUIC_SOCKFD Context;
	uint8_t Buffer[1024];
	int State = 0;
	QUIC_BUFFER SendBuffer;
	int ConnectState = 0;

	struct epoll_event Events[1024], Event;	
	Notify_Mes* Ptr = NULL;

    if (GetValue(argc, argv, "?") || GetValue(argc, argv, "help")) {
        printf("Usage:\n");
        printf(" tcpserver.exe [-target:<...>] [-port:<...>] \n");
        return 0;
    }
    const char* Target = "quic.westus.cloudapp.azure.com";
    uint16_t Port = 4433;

	TryGetValue(argc, argv, "target", &Target);
    TryGetValue(argc, argv, "port", &Port);

    if (QUIC_FAILED(MsQuicOpen(&(Context.MsQuic))))
    {
        printf("MsQuicOpen failed\n");
        return -1;
    }

    const QUIC_API_TABLE* MsQuic = Context.MsQuic;	
	
   	CHANNEL_DATA* MainChannel = (CHANNEL_DATA*)MsQuic->TcpSocket(PF_INET, SOCK_STREAM, 0, &Context);

    MsQuic->TcpBind(MainChannel, Target, Port);

	CHANNEL_DATA* EpChannel = (CHANNEL_DATA*)MsQuic->EpollCreate(&Context);
	if (EpChannel == NULL)
	{
		MsQuicClose(Context.MsQuic);
		return -1;
	}

    if (MsQuic->TcpListen(MainChannel, 100))
    {
        goto End;
    }

	Event.events = YMSQUIC_EPOLLIN;
	MsQuic->EpollCtl(EpChannel, YMSQUIC_EPOLL_CTL_ADD, MainChannel, &Event);
	while (1)
	{
		int Num = MsQuic->EpollWait(EpChannel, Events, MAX_EVENTS, -1);
		for (int i = 0; i < Num; i++)
		{
			Ptr = (Notify_Mes*)(Events[i].data.ptr);	
			if (Ptr->Channel == MainChannel)
			{
				CHANNEL_DATA *Channel = (CHANNEL_DATA*)MsQuic->TcpAccept(MainChannel);
				//if (Channel  == NULL) continue;
				Event.events = YMSQUIC_EPOLLIN;
				MsQuic->EpollCtl(EpChannel, YMSQUIC_EPOLL_CTL_ADD, Channel, &Event);	
				continue;
			}
			
			if (Ptr->Channel->EventType == YMSQUIC_EPOLLIN)
			{
        		memset(Buffer, 0, sizeof(Buffer));
        		SendBuffer.Length = MsQuic->TcpRecv(Ptr->Channel, Buffer, sizeof(Buffer), &ConnectState);
        		if (ConnectState)
        		{
            		goto End;
        		}

        		SendBuffer.Buffer= (uint8_t*)Buffer;
        		if (QUIC_FAILED(MsQuic->TcpSend(Ptr->Channel, &SendBuffer)))
        		{
            		printf("Server Send failed\n");
            		goto End;
        		}
			}
		}
	}

End:
	MsQuic->TcpClose(MainChannel);	
    return State;
}
