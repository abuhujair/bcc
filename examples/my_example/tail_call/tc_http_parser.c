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
#define MAX_PACKET_LENGTH1000 63535
#define MAX_ITER_PAYLOAD1000 2
#define PAYLOAD_LENGTH1000 1000
struct payload1000_t{
    __u8 data[PAYLOAD_LENGTH1000];
};

#define MAX_PACKET_LENGTH100 64535
#define MAX_ITER_PAYLOAD100 10
#define PAYLOAD_LENGTH100 100
struct payload100_t{
    __u8 data[PAYLOAD_LENGTH100];
};

#define MAX_PACKET_LENGTH10 65425
#define MAX_ITER_PAYLOAD10 10
#define PAYLOAD_LENGTH10 10
struct payload10_t{
    __u8 data[PAYLOAD_LENGTH10];
};

#define MAX_PACKET_LENGTH1 65525
#define MAX_ITER_PAYLOAD1 10
#define PAYLOAD_LENGTH1 1
struct payload1_t{
    __u8 data;
};

// Program Array
BPF_PROG_ARRAY(prog_array, 10);

// Tail State
struct tail_state_t{
    __u16 offset;
};
BPF_HASH(tail_state, struct __sk_buff *, struct tail_state_t);

#define check_offset(skb, offset, hdr, flag)          		    \
({								                            \
	__u16 len = sizeof(*hdr);			                    \
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

int http_payload_parser10(struct __sk_buff *skb){
    struct __sk_buff *sKey = skb;
    struct tail_state_t *state = tail_state.lookup(&sKey);
    if(state == NULL){
        goto PAYLOAD_PARSER_EXIT;
    }

    // Payload pointers
	struct payload10_t *payload10;
	struct payload1_t *payload1;

    __u16 hdrlen, offset;
    __u8 flag;
    hdrlen = 0;
    offset = state->offset < MAX_PACKET_LENGTH10 ? state->offset: 0;
    
    // Payload10
PAYLOAD_PARSER_10:;
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
PAYLOAD_PARSER_1:;
    bpf_trace_printk("Payload10: %d", offset+hdrlen);
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

PAYLOAD_PARSER_0:;
    offset += hdrlen;
    bpf_trace_printk("Payload1: %d", offset);

DELETE_STATE:;
    tail_state.delete(&sKey);
    bpf_trace_printk("Tail State Deleted %llx\n\n", sKey);

PAYLOAD_PARSER_EXIT:;   
    return TC_ACT_OK;
}

int http_payload_parser100(struct __sk_buff *skb){
    struct __sk_buff *sKey = skb;
    struct tail_state_t *state = tail_state.lookup(&sKey);
    if(state == NULL){
        goto PAYLOAD_PARSER_EXIT;
    }

    // Payload pointers
	struct payload100_t *payload100;

    __u16 hdrlen, offset;
    __u8 flag;
    hdrlen = 0;
    offset = state->offset < MAX_PACKET_LENGTH100 ? state->offset: 0;
    
    // Payload100
PAYLOAD_PARSER_100:;
    for(int loop = 0; loop < MAX_ITER_PAYLOAD100; loop++){
        offset += hdrlen;
        flag = 0;
        check_offset(skb, offset, payload100, flag);
        if(flag){
            offset -= hdrlen;
            goto UPDATE_STATE;
        }
        hdrlen = PAYLOAD_LENGTH100;
        bpf_trace_printk("%02x %04d", payload100->data[0],offset);
    }

UPDATE_STATE:;
    offset += hdrlen;
    bpf_trace_printk("Payload100: %d", offset);

    state->offset = offset;

    // Payload10
PAYLOAD_PARSER_10:;
    prog_array.call(skb, 4);

    // If tail call fails, delete state & return
DELETE_STATE:;
    tail_state.delete(&sKey);
    bpf_trace_printk("Tail State Deleted %llx\n\n", sKey);

PAYLOAD_PARSER_EXIT:;   
    return TC_ACT_OK;
}

int http_payload_parser1000(struct __sk_buff *skb){
    struct __sk_buff *sKey = skb;
    struct tail_state_t *state = tail_state.lookup(&sKey);
    if(state == NULL){
        goto PAYLOAD_PARSER_EXIT;
    }

    // Payload pointers
	struct payload1000_t *payload1000;

    __u16 hdrlen, offset;
    __u8 flag;
    hdrlen = 0;
    offset = state->offset < MAX_PACKET_LENGTH1000 ? state->offset: 0;
    
    // Payload1000
    for(int loop = 0; loop < MAX_ITER_PAYLOAD1000; loop++){
        offset += hdrlen;
        flag = 0;
        check_offset(skb, offset, payload1000, flag);
        if(flag){
            offset -= hdrlen;
            goto UPDATE_STATE;
        }
        hdrlen = PAYLOAD_LENGTH1000;
        bpf_trace_printk("%02x %04d", payload1000->data[0],offset);
    }

UPDATE_STATE:;
    offset += hdrlen;
    bpf_trace_printk("Payload1000: %d", offset);

    state->offset = offset;

    // If 1000 bytes are not available move to 100 bytes parser
    if(flag) goto PAYLOAD_PARSER_100;

PAYLOAD_PARSER_1000:
    prog_array.call(skb, 2);

    // Payload100
PAYLOAD_PARSER_100:;
    prog_array.call(skb, 3);

    // If tail call fails, delete state & return
DELETE_STATE:;
    tail_state.delete(&sKey);
    bpf_trace_printk("Tail State Deleted %llx\n\n", sKey);

PAYLOAD_PARSER_EXIT:;   
    return TC_ACT_OK;
}

int tcp_header_parser(struct __sk_buff *skb) {
    struct __sk_buff *sKey = skb;
    __u16 hdrlen, offset;
    __u8 flag;
    int i;

    // Header Pointers
	struct ethhdr *eth;
    struct iphdr *ip4;
	struct tcphdr *tcp;

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

    // TCP Header
    offset += hdrlen;
    flag = 0;
	check_offset(skb, offset, tcp, flag);
	if(flag)
		goto TCP_PARSER_EXIT;
	hdrlen = tcp->doff << 2;
    if(hdrlen < sizeof(*tcp) || tcp->source != htons(PORT_TO_MONITOR) || payload_length - iph - hdrlen <1)
        goto TCP_PARSER_EXIT;
    bpf_trace_printk("IPv4 header length: %d %d", iph, payload_length+ETH_HLEN);
    bpf_trace_printk("TCP header length: %d", hdrlen);


UPDATE_STATE:;
    offset += hdrlen;
    struct tail_state_t state = {
        .offset = 0,
    };
    state.offset = offset;
    tail_state.update(&sKey,&state);

TAIL_CALL:;
    prog_array.call(skb, 2);

DELETE_STATE:;
    tail_state.delete(&sKey);
    bpf_trace_printk("Tail State Deleted %llx\n\n", sKey);

TCP_PARSER_EXIT:;
    return TC_ACT_OK;
}