#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>


typedef struct ip_hdr
{
	unsigned char  ip_verlen;

	unsigned char  ip_tos;
	unsigned short ip_totallength;
	unsigned short ip_id;
	unsigned short ip_offset;
	unsigned char  ip_ttl;
	unsigned char  ip_protocol;
	unsigned short ip_checksum;
	unsigned int   ip_srcaddr;
	unsigned int   ip_destaddr;
} IPV4_HDR, IPV4_HEADER;

typedef struct icmp_header
{
	unsigned char   icmp_type;
	unsigned char   icmp_code;
	unsigned short  icmp_checksum;
	unsigned short  icmp_sequence;
	unsigned short  icmp_id;
} ICMP_HEADER;


//https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
typedef struct eth_header {
	unsigned char	h_dest[6];
	unsigned char   h_source[6];
	unsigned short	proto;
} ETH_HEADER;

#define DEFAULT_DATA_SIZE      32       // default data size
#define DEFAULT_SEND_COUNT     1        // number of ICMP requests to send

#define DEFAULT_RECV_TIMEOUT   6000     // six second

#define DEFAULT_TTL            128

#define MAX_RECV_BUF_LEN       0xFFFF   // Max incoming packet size.

gTtl = DEFAULT_TTL;                 // Default TTL value
int   gDataSize = DEFAULT_DATA_SIZE;      // Amount of data to send
BOOL  bRecordRoute = FALSE;               // Use IPv4 record route?
char* gDestination = "8.8.8.8",                // Destination
recvbuf[MAX_RECV_BUF_LEN];        // For received packets
int   recvbuflen = MAX_RECV_BUF_LEN;    // Length of received packets.


USHORT checksum(USHORT* buffer, int size)
{
	unsigned long cksum = 0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}


void SetIcmpSequence(char* buf)
{
	ULONG    sequence = 0;

	sequence = GetTickCount64();

	ICMP_HDR* icmpv4 = NULL;
	icmpv4 = (ICMP_HDR*)buf;
	icmpv4->icmp_sequence = (USHORT)sequence;

}

void ComputeIcmpChecksum(SOCKET s, char* buf, int packetlen, struct addrinfo* dest) {
	ICMP_HDR* icmpv4 = NULL;

	icmpv4 = (ICMP_HDR*)buf;
	icmpv4->icmp_checksum = 0;
	icmpv4->icmp_checksum = checksum((USHORT*)buf, packetlen);
}


int PostRecvfrom(SOCKET s, char* buf, int buflen, SOCKADDR* from, int* fromlen, WSAOVERLAPPED* ol) {
	WSABUF  wbuf;
	DWORD   flags,
		bytes;
	int     rc;

	wbuf.buf = buf;
	wbuf.len = buflen;

	flags = 0;

	rc = WSARecvFrom(
		s,
		&wbuf,
		1,
		&bytes,
		&flags,
		from,
		fromlen,
		ol,
		NULL
	);
	if (rc == SOCKET_ERROR)
	{
		if (WSAGetLastError() != WSA_IO_PENDING)
		{
			fprintf(stderr, "WSARecvFrom failed: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}
	}
	return NO_ERROR;
}

void PrintPayload(char* buf, int bytes)
{
	IPV4_HDR* iphdr = NULL;
	ICMP_HDR* icmphdr = NULL;

	ethhdr = (ETH_HEADER*)buf;
	iphdr = (IPV4_HDR*)(buf );
	icmphdr = (ICMP_HEADER*)(buf + sizeof(ETH_HEADER) + sizeof(IPV4_HDR));
	int hdrlen = (iphdr->ip_verlen & 0x0F) * 4;
	printf("\nCode %d\n", hdrlen);

	return;
}


struct addrinfo* ResolveAddress(char* addr, char* port, int af, int type, int proto)
{
	struct addrinfo hints,
		* res = NULL;
	int             rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = ((addr) ? 0 : AI_PASSIVE);
	hints.ai_family = af;
	hints.ai_socktype = type;
	hints.ai_protocol = proto;

	rc = getaddrinfo(
		addr,
		port,
		&hints,
		&res
	);
	if (rc != 0)
	{
		fprintf(stderr, "Invalid address %s, getaddrinfo failed: %d\n", addr, rc);
		return NULL;
	}
	return res;
}


int PrintAddress(SOCKADDR* sa, int salen) {
	char    host[NI_MAXHOST],
		serv[NI_MAXSERV];
	int     hostlen = NI_MAXHOST,
		servlen = NI_MAXSERV,
		rc;

	rc = getnameinfo(
		sa,
		salen,
		host,
		hostlen,
		serv,
		servlen,
		NI_NUMERICHOST | NI_NUMERICSERV
	);
	if (rc != 0)
	{
		fprintf(stderr, "%s: getnameinfo failed: %d\n", __FILE__, rc);
		return rc;
	}

	// If the port is zero then don't print it
	if (strcmp(serv, "0") != 0)
	{
		if (sa->sa_family == AF_INET)
			printf("[%s]:%s", host, serv);
		else
			printf("%s:%s", host, serv);
	}
	else
		printf("%s", host);

	return NO_ERROR;
}


int main(int argc, char** argv) {
	WSADATA            wsd;
	WSAOVERLAPPED      recvol;
	SOCKET             s = INVALID_SOCKET;
	char* icmpbuf = NULL;
	struct addrinfo* dest = NULL, * local = NULL;
	SOCKADDR_STORAGE   from;
	DWORD              bytes, flags;
	int                packetlen = 0, fromlen,time = 0, rc, i, status = 0;

	recvol.hEvent = WSA_INVALID_EVENT;


	if ((rc = WSAStartup(MAKEWORD(2, 2), &wsd)) != 0)
	{
		printf("WSAStartup() failed: %d\n", rc);
		status = -1;
		goto EXIT;
	}

	dest = ResolveAddress(
		gDestination,
		"0",
		AF_INET,
		0,
		0
	);
	if (dest == NULL)
	{
		printf("bad name %s\n", gDestination);
		status = -1;
		goto CLEANUP;
	}

	local = ResolveAddress(
		NULL,
		"0",
		AF_INET,
		0,
		0
	);
	if (local == NULL)
	{
		printf("Unable to obtain the bind address!\n");
		status = -1;
		goto CLEANUP;
	}

	s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (s == INVALID_SOCKET)
	{
		printf("socket failed: %d\n", WSAGetLastError());
		status = -1;
		goto CLEANUP;
	}

	packetlen += sizeof(ICMP_HDR);


	packetlen += gDataSize;

	icmpbuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetlen);
	if (icmpbuf == NULL)
	{
		fprintf(stderr, "HeapAlloc failed: %d\n", GetLastError());
		status = -1;
		goto CLEANUP;
	}


	ICMP_HDR* icmp_hdr = NULL;
	char* datapart = NULL;

	icmp_hdr = (ICMP_HDR*)icmpbuf;
	icmp_hdr->icmp_type = 8;
	icmp_hdr->icmp_code = 0;
	icmp_hdr->icmp_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->icmp_checksum = 0;
	icmp_hdr->icmp_sequence = 0;

	datapart = icmpbuf + sizeof(ICMP_HDR);

	memset(datapart, 'E', gDataSize);


	rc = bind(s, local->ai_addr, (int)local->ai_addrlen);
	if (rc == SOCKET_ERROR)
	{
		fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
		status = -1;
		goto CLEANUP;
	}

	memset(&recvol, 0, sizeof(recvol));
	recvol.hEvent = WSACreateEvent();
	if (recvol.hEvent == WSA_INVALID_EVENT)
	{
		fprintf(stderr, "WSACreateEvent failed: %d\n", WSAGetLastError());
		status = -1;
		goto CLEANUP;
	}

	fromlen = sizeof(from);
	PostRecvfrom(s, recvbuf, recvbuflen, (SOCKADDR*)&from, &fromlen, &recvol);

	printf("\nPinging ");
	PrintAddress(dest->ai_addr, (int)dest->ai_addrlen);
	printf(" with %d bytes of data\n\n", gDataSize);

	for (i = 0; i < DEFAULT_SEND_COUNT; i++)
	{
		ComputeIcmpChecksum(s, icmpbuf, packetlen, dest);

		time = GetTickCount64();
		rc = sendto(
			s,
			icmpbuf,
			packetlen,
			0,
			dest->ai_addr,
			(int)dest->ai_addrlen
		);
		if (rc == SOCKET_ERROR)
		{
			fprintf(stderr, "sendto failed: %d\n", WSAGetLastError());
			status = -1;
			goto CLEANUP;
		}

		rc = WaitForSingleObject((HANDLE)recvol.hEvent, DEFAULT_RECV_TIMEOUT);
		if (rc == WAIT_FAILED)
		{
			fprintf(stderr, "WaitForSingleObject failed: %d\n", GetLastError());
			status = -1;
			goto CLEANUP;
		}
		else if (rc == WAIT_TIMEOUT)
		{
			printf("Request timed out.\n");
		}
		else
		{
			rc = WSAGetOverlappedResult(
				s,
				&recvol,
				&bytes,
				FALSE,
				&flags
			);
			if (rc == FALSE)
			{
				fprintf(stderr, "WSAGetOverlappedResult failed: %d\n", WSAGetLastError());
			}
			time = GetTickCount64() - time;

			WSAResetEvent(recvol.hEvent);

			printf("Reply from ");
			PrintAddress((SOCKADDR*)&from, fromlen);
			if (time == 0)
				printf(": bytes=%d time<1ms TTL=%d\n", gDataSize, gTtl);
			else
				printf(": bytes=%d time=%dms TTL=%d\n", gDataSize, time, gTtl);

			PrintPayload(recvbuf, bytes);

			if (i < DEFAULT_SEND_COUNT - 1)
			{
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
