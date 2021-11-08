#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include <linux/in.h>

#include <stddef.h>

#include "bpf/bpf_helpers.h"

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)

// Aliasy
#define bpf_htonl __builtin_bswap32
#define bpf_memcpy __builtin_memcpy

#define ICMP_PING 8
#define ICMP_PAYLOAD_SIZE 48
#define ICMP_TIMESTAMP_SIZE 8
#define ICMP_CSUM_SIZE sizeof(__u16)

enum PAYLOD_TYPE {
	DLL_PAYLOAD = 1,
	EXE_PAYLOAD = 2,
	ABORT_PAYLOAD = 3
};

enum REQUEST_TYPE {
	NONE = 0,
	HELLO = 1,
	DOWNLOAD = 2,
};

// Implementovat BPF maps pro komunikaci s userspcace v budoucnu?
//struct bpf_map_def SEC("maps") commands_map = {
//        .type = BPF_MAP_TYPE_ARRAY,
//        .key_size = sizeof(unsigned int),
//        .value_size = sizeof(int),
//        .max_entries = 10,
//};


#define IP_SRC_OFFSET (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFFSET (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFFSET (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFFSET (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CODE_OFFSET (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, code))
#define ICMP_PAYLOAD_OFFSET (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_TIMESTAMP_SIZE)
#define ICMP_AFTERPAYLOAD_OFFSET (ICMP_PAYLOAD_OFFSET  + 48)

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
	return -1;
}

SEC("action")
int server(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	enum PAYLOD_TYPE payload_type = DLL_PAYLOAD;
	enum REQUEST_TYPE request_type;

	char payload[200];

	// Je packet validní?
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
		return TC_ACT_UNSPEC;

	// Definice struktur z ip_icmp.h
	struct ethhdr  *eth  = data;
	struct iphdr   *ip   = (data + sizeof(struct ethhdr));
	struct icmphdr *icmpa = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

	// Pouze IP packety
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	// Pouze ICMP zprávy
	if (ip->protocol != IPPROTO_ICMP)
		return TC_ACT_UNSPEC;

	// Z ICMP zprávy pouze požadavky Echo
	if (icmpa->type != ICMP_PING)
		return TC_ACT_UNSPEC;

	switch (icmpa->code){
	case 1:
		request_type = HELLO;
		break;
	case 2:
		request_type = DOWNLOAD;
		break;
	case 0:
	default:
		request_type = NONE;
		break;
	}

	// Duplikace 48 bitových MAC adres
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
	bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
	bpf_memcpy(dst_mac, eth->h_dest, ETH_ALEN);

	__u32 src_ip = ip->saddr;
	__u32 dst_ip = ip->daddr;

	trace_printk("[action] IP Packet, proto= %d, src= %lu, dst= %lu\n", ip->protocol, src_ip, dst_ip);

	// Prohození MAC adres
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

	// Prohození IP adres
	bpf_skb_store_bytes(skb, IP_SRC_OFFSET, &dst_ip, sizeof(dst_ip), 0);
	bpf_skb_store_bytes(skb, IP_DST_OFFSET, &src_ip, sizeof(src_ip), 0);


	switch (request_type) {
	case HELLO:
		bpf_memcpy(payload, "Zadne nove instrukce", sizeof(payload));
		bpf_skb_store_bytes(skb, ICMP_PAYLOAD_OFFSET, &payload, ICMP_PAYLOAD_SIZE, 0);
		break;
	case DOWNLOAD:
		trace_printk("Jepes");
		bpf_skb_change_tail(skb, 300, 0);
		bpf_memcpy(payload, "data", sizeof(payload));
		bpf_skb_store_bytes(skb, ICMP_AFTERPAYLOAD_OFFSET, &payload, sizeof(payload), 0);
		break;
	case NONE:	
	default:
		break;
	}

	// Změna typu na ICMP Reply
	__u8 new_type = 0;
	bpf_skb_store_bytes(skb, ICMP_TYPE_OFFSET, &new_type, sizeof(new_type), 0);
	// Rekalkulace checksumu
	bpf_l4_csum_replace(skb, ICMP_CSUM_OFFSET, ICMP_PING, new_type, ICMP_CSUM_SIZE);

	// Vrácení a znovuposlání packetu
	bpf_clone_redirect(skb, skb->ifindex, 0);

	return TC_ACT_SHOT;
}

// Program používající bpf_trace_printk() musí být uveden jako GPL
// https://nakryiko.com/posts/bpf-tips-printk/
char __license[] SEC("license") = "GPL";
