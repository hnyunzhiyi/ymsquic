1：QUIC, a multiplexed stream transport over UDP
======
	QUIC is an experimental protocol aimed at reducing web latency over that of TCP. On the surface, QUIC
	is very similar to TCP+TLS+HTTP/2 implemented on UDP. Because TCP is implemented in operating system kernels
	, and middlebox firmware, making significant changes to TCP is next to impossible. However, since QUIC is built
	on top of UDP,it suffers from no such limitations.

	Key features of QUIC over existing TCP+TLS+HTTP/2 include
	  * Dramatically reduced connection establishment time
	  * Improved congestion control
	  * Multiplexing without head of line blocking
	  * Forward error correction
	  * Connection migration

	See [Chromium QUIC Page](http://www.chromium.org/quic) for detailed information.
	
2：MsQuic
======
	Google QUIC is embedded in chromium source code, which is difficult to extract and cannot be used alone.Because 
	we introduced Microsoft's QUIC, MsQuic is a Microsoft implementation of the [IETF QUIC](https://tools.ietf.org
	/html/draft-ietf-quic-transport)protocol. It is cross platform, written in C and designed to be a general purpose
	QUIC library.

	> **Important** The MsQuic library, as well as the protocol itself, is still a work in progress. Version 1 is not 
	yet finalized and may continue to experience breaking changes until it is finalized.

	[![Build Status](https://dev.azure.com/ms/msquic/_apis/build/status/CI?branchName=main)]
		(https://dev.azure.com/ms/msquic/_build/latest?definitionId=347&branchName=main) 
	[![Test Status](https://img.shields.io/azure-devops/tests/ms/msquic/347/main)]
		(https://dev.azure.com/ms/msquic/_build/latest?definitionId=347&branchName=main) 
	[![Code Coverage](https://img.shields.io/azure-devops/coverage/ms/msquic/347/main)]
		(https://dev.azure.com/ms/msquic/_build/latest?definitionId=347&branchName=main) 
		![CodeQL](https://github.com/microsoft/msquic/workflows/CodeQL/badge.svg?branch=main) 
	[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/microsoft/msquic.svg?logo=lgtm&logoWidth=18)]
		(https://lgtm.com/projects/g/microsoft/msquic/context:cpp)

	## Protocol Features

	RFC: 9000, 9001, 9002 Draft: Datagram, Version Negotiation, Load Balancing, ACK Frequency, Perf Testing
	QUIC has many benefits when compared to existing TLS over TCP scenarios:

	  * Handshake authenticated with TLS 1.3
	  * All packets are encrypted
	  * Parallel streams of application data.
	  * Improved (compared to TCP) congestion control and loss recovery.
	  * Exchange application data in the first round trip (0-RTT).
	  * Survives a change in the clients IP address or port.
	  * Easily extendable for new features and extensions.
	  * Unreliable application data.
	  * Stateless load balancing.

	> **Important** The QUIC spec is currently in IETF last call and should move to IESG review by Nov 2020. From there 
	it will likely take a few months before it is finalized to RFC.

	Drafts: [Transport](https://tools.ietf.org/html/draft-ietf-quic-transport), 
		[TLS](https://tools.ietf.org/html/draft-ietf-quic-tls),
		[Recovery](https://tools.ietf.org/html/draft-ietf-quic-recovery), 
		[Datagram](https://tools.ietf.org/html/draft-ietf-quic-datagram),
		[Load Balancing](https://tools.ietf.org/html/draft-ietf-quic-load-balancers)

	> **Important** Several QUIC protocol features are not yet fully implemented:
	>  * 0-RTT
	>  * Client-side Migration
	>  * Server Preferred Address
	>  * Path MTU Discovery

	## Library Features
	  * Cross-platform support.
	  * Optimized for client and server.
	  * Optimized for maximal throughput and minimal latency.
	  * Asynchronous IO.
	  * Receive side scaling (RSS).
	  * UDP send and receive coalescing support. 
	  * Simulates TCP to encapsulate interfaces for sending and receiving data

	# Platform Support

	MsQuic currently officially supports the following platform configurations.
	Information on support for MsQuic itself is located in [Support.md.](./docs/Support.md)

	## Windows 10

	On Windows 10, MsQuic relies on built-in support from [Schannel](https://docs.microsoft.com/en-us/windows/win32/com/schannel) 
	for TLS 1.3 functionality. MsQuic is shipped in-box in the Windows kernel in the form of the `msquic.sys` driver, to support 
	built-in HTTP and SMB features. User mode applications use `msquic.dll` (built from here) and package it with their app.

	> **Important** This configuration requires running the latest [Windows Insider Preview Builds](https://insider.windows.com/en-us/) 
	for Schannel's TLS 1.3 support.

	> **Important** This configuration does not support 0-RTT due to Schannel's current lack of support.

	## Linux

	On Linux, MsQuic relies on [OpenSSL](https://www.openssl.org/) for TLS 1.3 functionality.

	> **Important** This configuration relies on an [outstanding pull request](https://github.com/openssl/openssl/pull/8797)
	 to OpenSSL master for QUIC/TLS support. It is still currently unknown as to when it will be merged into master. 
	 See [here](https://www.openssl.org/blog/blog/2020/02/17/QUIC-and-OpenSSL/) for more details.

	> **Important** This configuration does not support 0-RTT. Complete integration with OpenSSL is an ongoing effort.

	## Other

	For testing or experimentation purposes, MsQuic may be built with other configurations, but they are not to be considered 
	officially supported unless they are listed above. Any bugs found while using these configurations may be looked at, but
	no guarantees are provided that they will be fixed.

	# Documentation

	  * For building the library, see the [Build docs](./docs/BUILD.md).
	  * For using the library, see the [API docs](./docs/API.md) or the [Sample](./src/tools/sample/sample.cpp).
	  * For other frequently asked questions, see the [FAQs](./docs/FAQ.md).

	# Contributing

	For information on contributing, please see our [contribution guidlines](./.github/CONTRIBUTING.md).

	> **Important** - We are still bringing up important regression tests for the core code. Until they are onboarded, any external
	contributions to the [core](./src/core) or kernel mode files in the [platform](./src/platform) will not be accepted. This is only
	a **temporary restriction** and we are working to complete it by the end of 2020.

3: Yarely Microsoft Quick UDP Internet 
======
	Because Microsoft's QUIC relies on high environmental requirements when compiling in the Linux environment,
	lower version systems may be incompatible and the compilation steps are cumbersome, 
	so we have added a Ymsquic version adapted to the Linux system and add call interfaces like POSIX Socket API.
	
	1: How to build Ymsquic
	  Please refer to the BUILD.md file in the folder doc under the current path.
 
	2: How to use Ymsquic samples 
	example 1>: 
		client: ./quicipclient -target:<destination ip>  [-local:<local ip> ] [-port:<default port:4444>]
		server: ./quicipserver -selfsign

	example 2>:
		client: ./quicpost -server:<destination IP or domain>  [-port:<default port:4433>] -file:<Upload files under specific path> 
		server: ./quicinteropserver -listen:<listening ip or *> [-retry:<repeat times>] [-thumbprint:<cert_thumbprint>] 
				-root:<file path> [-upload:<save file path>]
		
	example 3>:
		client: ./quicreach [-server:<name>] [-ip:<ip>] [-port:<number>] [-alpn:<alpn>]
		server: ./quicinteropserver -listen:<listening ip or *> [-retry:<repeat times>] [-thumbprint:<cert_thumbprint>] -root:<file path> 
				[-upload:<download file>]

	example 4>:
		client: ./spinquic -client -target:<destination ip or domain> [-dstport:<default port:9999>] [-alpn:<default value:spin>] 
				[-timeout:<count_ms>]
		server: ./spinquic -server -target:<listening ip or *> [-dstport:<connect server port>] [-apln:<connect server alpn>] 
				[-timeout:<count_ms>]
	example 5>:
		client: ./tcpclient -target:<destination ip or domain> [-port:<default port:4444>]
		server: ./tcpserver -target:<destination ip or domain> [-port:<default port:4444>]
    
	
