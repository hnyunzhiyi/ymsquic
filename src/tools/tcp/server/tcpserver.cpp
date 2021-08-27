#include <quic_tls.h> 
#include <msquichelper.h>
#include "msquic.h"

#define MAX_EVENTS 128

typedef struct Recv_Message
{
	QUIC_SOCKFD *Context;
	CHANNEL_DATA *Channel;
}Recv_Mess;

static void *TestReachability(void*fig)
{
	int State = 0, ConnectState = 0;
	uint8_t Buffer[1024];
	uint8_t *Pt = NULL;
	uint32_t Len = 0;
	QUIC_BUFFER SendBuffer;
	Recv_Mess *Config = (Recv_Mess*)fig;
	const QUIC_API_TABLE* MsQuic = Config->Context->MsQuic;
	
	while (1)
	{	
		QuicEventWaitForever(Config->Channel->RecvList.REvent);
		memset(Buffer, 0, sizeof(Buffer));
		SendBuffer.Length = MsQuic->TcpRecv(Config->Channel, Buffer, sizeof(Buffer), &ConnectState);
    	if (ConnectState)
		{
			goto End;
    	}
		SendBuffer.Buffer= (uint8_t*)Buffer;
		if (!State)
		{
			if (strncmp(GET_CHANNELID, (char*)Buffer, strlen(GET_CHANNELID)))
    		{
				printf("GET Channel id failed:%s--Length:%u\n", (char*)Buffer, SendBuffer.Length);				
				goto End;
			}

			Config->Channel->ChannelID = __sync_fetch_and_add(&Config->Context->ChannelID, 1);	
			Pt = &Buffer[14];
			Len = sizeof(Config->Channel->ChannelID) + sizeof("\r\n");	
			snprintf((char*)Pt, Len, "%u\r\n", Config->Channel->ChannelID);			
			SendBuffer.Buffer = Buffer;
			SendBuffer.Length += Len;
			State = 1;	
		}
	
		if (QUIC_FAILED(MsQuic->TcpSend(Config->Channel, &SendBuffer)))
    	{
        	printf("Server Send failed\n");
    		goto End;
    	}
	}
	
End:
	MsQuic->TcpClose(Config->Channel);
	QUIC_THREAD_RETURN(0);	
}

static void start_pthread(CHANNEL_DATA* Channel, QUIC_SOCKFD *Context)
{
	uint32_t ProCount = QuicProcActiveCount();
	Recv_Mess* Tmp = NULL;
	QUIC_THREAD_CONFIG Config = { 0, 0, NULL, TestReachability, nullptr };
	QUIC_THREAD Thread;

	Config.Flags = QUIC_THREAD_FLAG_SET_AFFINITIZE;
    Config.IdealProcessor = rand()%ProCount;
    Tmp = (Recv_Mess*) malloc(sizeof(Recv_Mess));
    Tmp->Context = Context;
    Tmp->Channel = Channel;
    Config.Context = (void*)Tmp;

    if (QUIC_FAILED(QuicThreadCreate(&Config, &Thread))) {
    	printf("QuicThreadCreate failed.\n");
        exit(1);
    }

}

int main(int argc, char *argv[])
{
    QUIC_SOCKFD Context;
	uint8_t Buffer[1024];
	int State = 0;
	QUIC_BUFFER SendBuffer;
	struct epoll_event Events[1024], Event;	
	Notify_Mes* Ptr = NULL;

    if (GetValue(argc, argv, "?") || GetValue(argc, argv, "help")) {
        printf("Usage:\n");
        printf(" tcpserver.exe [-target:<...>] [-port:<...>] \n");
        return 0;
    }
    const char* Target = "quic.westus.cloudapp.azure.com";
    const char* Port = "4433";

	TryGetValue(argc, argv, "target", &Target);
    TryGetValue(argc, argv, "port", &Port);


    if (QUIC_FAILED(MsQuicOpen(&(Context.MsQuic))))
    {
        printf("MsQuicOpen failed\n");
        return -1;
    }

    const QUIC_API_TABLE* MsQuic = Context.MsQuic;	
	
   	CHANNEL_DATA* MainChannel = (CHANNEL_DATA*)MsQuic->TcpSocket(PF_INET, SOCK_STREAM, 0, &Context);

    MsQuic->TcpBind(MainChannel, Target, atoi(Port));

	CHANNEL_DATA* EpChannel = (CHANNEL_DATA*)MsQuic->EpollCreate(&Context);
	if (EpChannel == NULL)
	{
		MsQuicClose(Context.MsQuic);
		return -1;
	}

    if (MsQuic->TcpListen(MainChannel))
    {
        if (Context.Configuration)
		{
			FreeServerConfiguration(MsQuic, Context.Configuration);
		}
		State = -1;
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
				Event.events = YMSQUIC_EPOLLIN;
				MsQuic->EpollCtl(EpChannel, YMSQUIC_EPOLL_CTL_ADD, Channel, &Event);
				start_pthread(Channel, &Context);
				continue;
			}
			else 
			{
				if (Ptr->Channel->EventType == YMSQUIC_EPOLLIN)
				{
					QuicEventSet(Ptr->Channel->RecvList.REvent); 
				}
			}
		}

	}

End:
	MsQuic->TcpClose(MainChannel);	
    return State;
}
