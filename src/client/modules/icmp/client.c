#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#include "icmp_headers.h"
#include "../../include/requests.h"

int PostRecvfrom(SOCKET s, char* buf, int buflen, SOCKADDR* from, int* fromlen, WSAOVERLAPPED* ol) {
	WSABUF	wbuf;
	DWORD   flags,bytes;
	int	rc;

	wbuf.buf = buf;
	wbuf.len = buflen;

	flags = 0;

	rc = WSARecvFrom(s, &wbuf, 1, &bytes, &flags, from, fromlen, ol,NULL);
	if (rc == SOCKET_ERROR) {
		if (WSAGetLastError() != WSA_IO_PENDING) {
			fprintf(stderr, "WSARecvFrom failed: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}
	}
	return NO_ERROR;
}

char *GetPayload(char* buf, int bytes)
{
	IPV4_HDR* iphdr = NULL;
	ICMP_HEADER* icmphdr = NULL;

	iphdr = (IPV4_HDR*)(buf );
	icmphdr = (ICMP_HEADER*)(buf + sizeof(IPV4_HDR));
	int hdrlen = (iphdr->ip_verlen & 0x0F) * 4;
	printf("\nCode %d\n", hdrlen);

	return "";
}


struct addrinfo* ResolveAddress(char* addr, char* port, int af, int type, int proto) {
	struct addrinfo hints,*res = NULL;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = ((addr) ? 0 : AI_PASSIVE);
	hints.ai_family = af;
	hints.ai_socktype = type;
	hints.ai_protocol = proto;

	rc = getaddrinfo(addr,port,&hints,&res);
	
	if (rc != 0) {
		fprintf(stderr, "Invalid address %s, getaddrinfo failed: %d\n", addr, rc);
		return NULL;
	}
	return res;
}

int SendICMP(char *gDestination, REQUEST_TYPE request_type) {
	WSADATA	wsd;
	WSAOVERLAPPED recvol;
	SOCKET s = INVALID_SOCKET;
	char* icmpbuf = NULL;
	struct addrinfo* dest = NULL, * local = NULL;
	SOCKADDR_STORAGE from;
	DWORD bytes, flags;
	int	packetlen = 0, fromlen,time = 0, rc, i, status = 0;

	recvol.hEvent = WSA_INVALID_EVENT;

	// Inicializace - WSAStartup
	if ((rc = WSAStartup(MAKEWORD(2, 2), &wsd)) != 0)
	{
		printf("WSAStartup() failed: %d\n", rc);
		status = -1;
		goto EXIT;
	}

	// Cílová adresa
	dest = ResolveAddress(gDestination, "0", AF_INET, 0, 0);
	
	if (dest == NULL) {
		printf("bad name %s\n", gDestination);
		status = -1;
		goto CLEANUP;
	}

	local = ResolveAddress(NULL,"0",AF_INET,0,0);

	if (local == NULL) {
		printf("Unable to obtain the bind address!\n");
		status = -1;
		goto CLEANUP;
	}

	// Vytvoøení RAW IPv4 socketu pro ICMP
	s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (s == INVALID_SOCKET) {
		printf("socket failed: %d\n", WSAGetLastError());
		status = -1;
		goto CLEANUP;
	}

	packetlen += sizeof(ICMP_HEADER);
	packetlen += gDataSize;

	icmpbuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetlen);
	if (icmpbuf == NULL) {
		fprintf(stderr, "HeapAlloc failed: %d\n", GetLastError());
		status = -1;
		goto CLEANUP;
	}

	// ICMP packet
	ICMP_HEADER* icmp_hdr = NULL;
	char* datapart = NULL;

	icmp_hdr = (ICMP_HEADER*)icmpbuf;
	// ICMP požadavek typu ECHO
	icmp_hdr->icmp_type = 8;

	switch (request_type) {
		default:
		HELLO:
			icmp_hdr->icmp_code = 0;
			break;
		// Pro ostatní jsou potøeba administrtorská práva :/
		GET_INFORMATION:
			icmp_hdr->icmp_code = 1;
			break;
		GET_PAYLOAD:
			icmp_hdr->icmp_code = 2;
			break;
	}

	icmp_hdr->icmp_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->icmp_checksum = 0;
	icmp_hdr->icmp_sequence = 0;

	datapart = icmpbuf + sizeof(ICMP_HEADER);

	memset(datapart, 'E', gDataSize);


	rc = bind(s, local->ai_addr, (int)local->ai_addrlen);
	if (rc == SOCKET_ERROR) {
		fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
		status = -1;
		goto CLEANUP;
	}

	memset(&recvol, 0, sizeof(recvol));
	recvol.hEvent = WSACreateEvent();
	if (recvol.hEvent == WSA_INVALID_EVENT) {
		fprintf(stderr, "WSACreateEvent failed: %d\n", WSAGetLastError());
		status = -1;
		goto CLEANUP;
	}

	fromlen = sizeof(from);
	PostRecvfrom(s, recvbuf, recvbuflen, (SOCKADDR*)&from, &fromlen, &recvol);

	printf("\nPinging");
	printf("with %d bytes of data\n\n", gDataSize);

	for (i = 0; i < DEFAULT_SEND_COUNT; i++) {
		ComputeIcmpChecksum(s, icmpbuf, packetlen, dest);

		time = GetTickCount64();
		rc = sendto(s, icmpbuf, packetlen,0, dest->ai_addr, (int)dest->ai_addrlen);

		if (rc == SOCKET_ERROR) {
			fprintf(stderr, "sendto failed: %d\n", WSAGetLastError());
			status = -1;
			goto CLEANUP;
		}

		rc = WaitForSingleObject((HANDLE)recvol.hEvent, DEFAULT_RECV_TIMEOUT);
		if (rc == WAIT_FAILED) {
			fprintf(stderr, "WaitForSingleObject failed: %d\n", GetLastError());
			status = -1;
			goto CLEANUP;
		}
		else if (rc == WAIT_TIMEOUT) {
			printf("Request timed out.\n");
		}
		else {
			rc = WSAGetOverlappedResult(s, &recvol, &bytes, FALSE, &flags);
			if (rc == FALSE) {
				fprintf(stderr, "WSAGetOverlappedResult failed: %d\n", WSAGetLastError());
			}

			WSAResetEvent(recvol.hEvent);

			printf("Reply from");
			printf(": bytes=%d time<1ms TTL=%d\n", gDataSize, gTtl);

			if (i < DEFAULT_SEND_COUNT - 1) {
				fromlen = sizeof(from);
				PostRecvfrom(s, recvbuf, recvbuflen, (SOCKADDR*)&from, &fromlen, &recvol);
			}
		}
		Sleep(1000);
	}

CLEANUP:
	if (dest)
		freeaddrinfo(dest);
	if (local)
		freeaddrinfo(local);
	if (s != INVALID_SOCKET)
		closesocket(s);
	if (recvol.hEvent != WSA_INVALID_EVENT)
		WSACloseEvent(recvol.hEvent);
	if (icmpbuf)
		HeapFree(GetProcessHeap(), 0, icmpbuf);
	WSACleanup();

EXIT:
	return status;
}