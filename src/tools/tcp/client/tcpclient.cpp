#define ENABLE_QUIC_PRINTF
#include <msquichelper.h>
#include <unistd.h>

int getHostNameIpAddress(const char* domainName, struct sockaddr* addr) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int errcode;
	char addrstr[INET6_ADDRSTRLEN];
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
				ptr = &((struct sockaddr_in*) rp->ai_addr)->sin_addr;
				((struct sockaddr_in*) addr)->sin_family = AF_INET;
				memcpy(&((struct sockaddr_in*) addr)->sin_addr, ptr, sizeof(struct in_addr));
				inet_ntop(rp->ai_family, ptr, addrstr, INET6_ADDRSTRLEN);
				break;
			case AF_INET6:
				ptr = &((struct sockaddr_in6*) rp->ai_addr)->sin6_addr;
				((struct sockaddr_in6*) addr)->sin6_family = AF_INET6;
				memcpy(&((struct sockaddr_in6*) addr)->sin6_addr, ptr, sizeof(struct in6_addr));
				inet_ntop(rp->ai_family, ptr, addrstr, INET6_ADDRSTRLEN);
				break;
		}

		printf("IPv%d  address = %s", rp->ai_family == AF_INET6 ? 6 : 4, addrstr);
	}

	freeaddrinfo(result);           /* No longer needed */

	return 0;
}

int main(int argc, char *argv[])
{
	QUIC_SOCKFD Context;
    char Addr[32];
	int  State = 0;
	uint8_t data[200];
	uint32_t Result = 0, z = 10000;	
	QUIC_BUFFER SendBuffer;
	struct sockaddr_in6 addr;
	struct sockaddr_in * paddr = (struct sockaddr_in *) &addr;

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

	memset(&addr, 0, sizeof(addr));
	getHostNameIpAddress(Target, (struct sockaddr *) &addr);
	if (addr.sin6_family == AF_INET)
		paddr->sin_port = htons(Port);
	else if (addr.sin6_family == AF_INET6)
		addr.sin6_port = htons(Port);
	
	if (QUIC_FAILED(MsQuic->TcpConnect(MChannel, (struct sockaddr *) &addr, sizeof(addr))))
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
 
