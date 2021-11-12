typedef struct ip_hdr {
	UCHAR	ip_verlen;

	UCHAR	ip_tos;
	USHORT	ip_totallength;
	USHORT	ip_id;
	USHORT	ip_offset;
	UCHAR	ip_ttl;
	UCHAR	ip_protocol;
	USHORT	ip_checksum;
	UINT	ip_srcaddr;
	UINT	ip_destaddr;
} IPV4_HDR, IPV4_HEADER;

typedef struct icmp_header {
	UCHAR   icmp_type;
	UCHAR   icmp_code;
	USHORT  icmp_checksum;
	USHORT  icmp_sequence;
	USHORT  icmp_id;
} ICMP_HEADER;


//https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
typedef struct eth_header {
	UCHAR	h_dest[6];
	UCHAR   h_source[6];
	USHORT	proto;
} ETH_HEADER;


#define DEFAULT_RECV_TIMEOUT   6000     // 6 sekund

#define MAX_RECV_BUF_LEN       0xFFFF   // Velikost pøijatého packetu

gTtl = 128;								// TTL hodnota



USHORT checksum(USHORT* buffer, INT size) {
	ULONG cksum = 0;

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


VOID SetIcmpSequence(LPSTR buf) {
	ULONGLONG sequence = 0;
	sequence = GetTickCount64();

	ICMP_HEADER* icmpv4 = NULL;
	icmpv4 = (ICMP_HEADER*)buf;
	icmpv4->icmp_sequence = (USHORT)sequence;

}

VOID ComputeIcmpChecksum(SOCKET s, LPSTR buf, INT packetlen, struct addrinfo* dest) {
	ICMP_HEADER* icmpv4 = NULL;

	icmpv4 = (ICMP_HEADER*)buf;
	icmpv4->icmp_checksum = 0;
	icmpv4->icmp_checksum = checksum((USHORT*)buf, packetlen);
}