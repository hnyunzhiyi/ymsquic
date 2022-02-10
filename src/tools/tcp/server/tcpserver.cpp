#include <quic_tls.h>
#include <msquichelper.h>
#include "msquic.h"

#define MAX_EVENTS 128

typedef struct Recv_Message {
	QUIC_SOCKFD *Context;
	CHANNEL_DATA *Channel;
} Recv_Mess;

int getHostNameIpAddress(const char* domainName, struct sockaddr* addr) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int errcode;
	char addrstr[100];
	void* ptr;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	errcode = getaddrinfo(domainName, NULL, &hints, &result);
	if (errcode != 0) {
		printf("getaddrinfo failed with error: %s\n", gai_strerror(errcode));
		return errcode;
	}

	printf("Host: %s\n", domainName);

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		switch (rp->ai_family) {
			case AF_INET:
				ptr = &((struct sockaddr_in*) rp->ai_addr)->sin_addr;;
				((struct sockaddr_in*) addr)->sin_family = AF_INET;
				memcpy(&((struct sockaddr_in*) addr)->sin_addr, ptr, sizeof(struct in_addr));
				inet_ntop(rp->ai_family, ptr, addrstr, 100);
				break;
			case AF_INET6:
				ptr = &((struct sockaddr_in6*) rp->ai_addr)->sin6_addr;
				((struct sockaddr_in6*) addr)->sin6_family = AF_INET6;
				memcpy(&((struct sockaddr_in6*) addr)->sin6_addr, ptr, sizeof(struct in6_addr));
				inet_ntop(rp->ai_family, ptr, addrstr, 100);
				break;
		}

		printf("IPv%d  address = %s", rp->ai_family == AF_INET6 ? 6 : 4, addrstr);
	}

	freeaddrinfo(result);           /* No longer needed */

	return 0;
}

int main(int argc, char *argv[]) {
	QUIC_SOCKFD Context;
	uint8_t Buffer[1024];
	int State = 0;
	QUIC_BUFFER SendBuffer;
	int ConnectState = 0;
	struct sockaddr_in6 addr;
	struct sockaddr_in * paddr = (struct sockaddr_in *) &addr;

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

	if (QUIC_FAILED(MsQuicOpen(&(Context.MsQuic)))) {
		printf("MsQuicOpen failed\n");
		return -1;
	}

	const QUIC_API_TABLE* MsQuic = Context.MsQuic;

	CHANNEL_DATA* MainChannel = (CHANNEL_DATA*)MsQuic->TcpSocket(PF_INET, SOCK_STREAM, 0, &Context);

	memset(&addr, 0, sizeof(addr));
	getHostNameIpAddress(Target, (struct sockaddr *) &addr);
	if (addr.sin6_family == AF_INET)
		paddr->sin_port = htons(Port);
	else if (addr.sin6_family == AF_INET6)
		addr.sin6_port = htons(Port);

	MsQuic->TcpBind(MainChannel, (struct sockaddr *) &addr, sizeof(addr));

	CHANNEL_DATA* EpChannel = (CHANNEL_DATA*)MsQuic->EpollCreate(&Context);
	if (EpChannel == NULL) {
		MsQuicClose(Context.MsQuic);
		return -1;
	}

	if (MsQuic->TcpListen(MainChannel, 100)) {
		goto End;
	}

	Event.events = YMSQUIC_EPOLLIN;
	MsQuic->EpollCtl(EpChannel, YMSQUIC_EPOLL_CTL_ADD, MainChannel, &Event);
	while (1) {
		int Num = MsQuic->EpollWait(EpChannel, Events, MAX_EVENTS, -1);
		for (int i = 0; i < Num; i++) {
			Ptr = (Notify_Mes*)(Events[i].data.ptr);
			if (Ptr->Channel == MainChannel) {
				CHANNEL_DATA *Channel = (CHANNEL_DATA*)MsQuic->TcpAccept(MainChannel);
				//if (Channel  == NULL) continue;
				Event.events = YMSQUIC_EPOLLIN;
				MsQuic->EpollCtl(EpChannel, YMSQUIC_EPOLL_CTL_ADD, Channel, &Event);
				continue;
			}

			if (Ptr->Channel->EventType == YMSQUIC_EPOLLIN) {
				memset(Buffer, 0, sizeof(Buffer));
				SendBuffer.Length = MsQuic->TcpRecv(Ptr->Channel, Buffer, sizeof(Buffer), &ConnectState);
				if (ConnectState) {
					goto End;
				}

				SendBuffer.Buffer= (uint8_t*)Buffer;
				if (QUIC_FAILED(MsQuic->TcpSend(Ptr->Channel, &SendBuffer))) {
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
