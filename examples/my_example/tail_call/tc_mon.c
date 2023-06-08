#include <uapi/linux/pkt_cls.h>

#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>

// Layer2 Constants
#define ETH_HLEN 14

// Layer3 Constants
#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1

// Layer4 Constants

// Layer7 Constants
// HTTP
#define MIN_HTTP_TLEN 50
#define OK_STATUS 200
#define NOT_FOUND_STATUS 404

// Application Requirement
#define PORT_TO_MONITOR 80

// Payload Struct
#define MAX_ITER_PAYLOAD1000 5
#define PAYLOAD_LENGTH1000 1000
struct payload1000_t{
    __u8 data[PAYLOAD_LENGTH1000];
};

#define MAX_ITER_PAYLOAD100 10
#define PAYLOAD_LENGTH100 100
struct payload100_t{
    __u8 data[PAYLOAD_LENGTH100];
};

#define MAX_ITER_PAYLOAD10 10
#define PAYLOAD_LENGTH10 10
struct payload10_t{
    __u8 data[PAYLOAD_LENGTH10];
};

#define MAX_ITER_PAYLOAD1 10
#define PAYLOAD_LENGTH1 1
struct payload1_t{
    __u8 data;
};

#define check_offset(skb, offset, hdr, flag)          		    \
({								                            \
	__u32 len = sizeof(*hdr);			                    \
								                            \
	void *data = (void *)(long)skb->data + offset;		    \
	void *data_end = (void *)(long)skb->data_end;		    \
								                            \
	if (data + len > data_end)				                \
		bpf_skb_pull_data(skb, offset + len);		        \
								                            \
	data = (void *)(long)skb->data + offset;		        \
	data_end = (void *)(long)skb->data_end;			        \
	if (data + len <= data_end){                            \
    	hdr = data;			                                \
    }else			                                        \
		flag = 1;				                            \
})

int tcp_header_parser(struct __sk_buff *skb) {
    __u32 hdrlen, offset;
    __u8 flag;
    int i;

    // Header Pointers
	struct ethhdr *eth;
    struct iphdr *ip4;
	struct tcphdr *tcp;

    // Payload pointers
	struct payload1000_t *payload1000;
	struct payload100_t *payload100;
	struct payload10_t *payload10;
	struct payload1_t *payload1;

    // Ethernet Header
    offset = 0;
    flag = 0;
    check_offset(skb, offset, eth,flag);
    if(flag)
		goto TCP_PARSER_EXIT;
	if(eth->h_proto != htons(ETH_P_IP))
        goto TCP_PARSER_EXIT;
	
    // IPv4 Header
	offset = ETH_HLEN;
    flag = 0;
    check_offset(skb, offset, ip4, flag);
    if(flag)
		goto TCP_PARSER_EXIT;
	hdrlen = ip4->ihl << 2;
    __u8 iph = hdrlen;
    __u16 payload_length = ntohs(ip4->tot_len);
	if (hdrlen < sizeof(*ip4) || ip4->protocol != IP_TCP)
		goto TCP_PARSER_EXIT;
    bpf_trace_printk("IPv4 header length: %d %d", hdrlen, payload_length+ETH_HLEN);

    // TCP Header
    offset += hdrlen;
    flag = 0;
	check_offset(skb, offset, tcp, flag);
	if(flag)
		goto TCP_PARSER_EXIT;
	hdrlen = tcp->doff << 2;
    if(hdrlen < sizeof(*tcp) || tcp->source != htons(PORT_TO_MONITOR) || payload_length - iph - hdrlen <1)
        goto TCP_PARSER_EXIT;
    bpf_trace_printk("TCP header length: %d", hdrlen);

    // Payload1000
PAYLOAD_PARSER_1000:
    for(int loop = 0; loop < MAX_ITER_PAYLOAD1000; loop++){
        offset += hdrlen;
        flag = 0;
        check_offset(skb, offset, payload1000, flag);
        if(flag){
            offset -= hdrlen;
            goto PAYLOAD_PARSER_100;
        }
        hdrlen = PAYLOAD_LENGTH1000;
        bpf_trace_printk("%02x %04d", payload1000->data[0],offset);
    }

    // Payload100
PAYLOAD_PARSER_100:
    bpf_trace_printk("Payload1000: %d", offset);
    for(int loop = 0; loop < MAX_ITER_PAYLOAD100; loop++){
        offset += hdrlen;
        flag = 0;
        check_offset(skb, offset, payload100, flag);
        if(flag){
            offset -= hdrlen;
            goto PAYLOAD_PARSER_10;
        }
        hdrlen = PAYLOAD_LENGTH100;
        bpf_trace_printk("%02x %04d", payload100->data[0],offset);
    }

    // Payload10
PAYLOAD_PARSER_10:
    bpf_trace_printk("Payload100: %d", offset);
    for(int loop = 0; loop < MAX_ITER_PAYLOAD10; loop++){
        offset += hdrlen;
        flag = 0;
        check_offset(skb, offset, payload10, flag);
        if(flag){
            offset -= hdrlen;
            goto PAYLOAD_PARSER_1;
        }
        hdrlen = PAYLOAD_LENGTH10;
        bpf_trace_printk("%02x %04d", payload10->data[0],offset);
    }

    // Payload1
PAYLOAD_PARSER_1:
    bpf_trace_printk("Payload10: %d", offset);
    for(int loop = 0; loop < MAX_ITER_PAYLOAD1; loop++){
        offset += hdrlen;
        flag = 0;
        check_offset(skb, offset, payload1, flag);
        if(flag){
            offset -= hdrlen;
            goto PAYLOAD_PARSER_0;
        }
        hdrlen = PAYLOAD_LENGTH1;
        bpf_trace_printk("%02x %04d", payload1->data,offset);
    }

PAYLOAD_PARSER_0:
    offset += hdrlen;
    bpf_trace_printk("Payload1: %d", offset);

TCP_PARSER_EXIT:
    return TC_ACT_OK;
}