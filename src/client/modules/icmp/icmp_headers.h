#include <stdlib.h>

typedef struct ip_hdr {
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

typedef struct icmp_header {
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


#define DEFAULT_RECV_TIMEOUT   6000     // 6 sekund

#define MAX_RECV_BUF_LEN       0xFFFF   // Velikost pøijatého packetu

gTtl = 128;								// TTL hodnota



USHORT checksum(USHORT* buffer, int size) {
	unsigned long cksum = 0;

	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size) {
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}


void SetIcmpSequence(char* buf) {
	ULONGLONG sequence = 0;
	sequence = GetTickCount64();

	ICMP_HEADER* icmpv4 = NULL;
	icmpv4 = (ICMP_HEADER*)buf;
	icmpv4->icmp_sequence = (USHORT)sequence;

}

void ComputeIcmpChecksum(SOCKET s, char* buf, int packetlen, struct addrinfo* dest) {
	ICMP_HEADER* icmpv4 = NULL;

	icmpv4 = (ICMP_HEADER*)buf;
	icmpv4->icmp_checksum = 0;
	icmpv4->icmp_checksum = checksum((USHORT*)buf, packetlen);
}