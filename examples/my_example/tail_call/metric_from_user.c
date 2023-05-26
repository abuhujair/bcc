#include <bcc/proto.h>
#include <net/sock.h>

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

// MAP to store the index of all programs
BPF_PROG_ARRAY(prog_array, 10);

// MAP to store metric by user
#define TAG_LENGTH 10
struct metric_key{
    __u16 src_port;
};
struct metric_data{
    char tag[TAG_LENGTH];
    __u8 tag_length;
    __u8 tag_lps[TAG_LENGTH];
};
BPF_HASH(user_metric,struct metric_key, struct metric_data);

// MAP to store state in between tail_call
struct tail_call_state{
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 tail_call_count;
};
BPF_HASH(tail_state, struct __sk_buff *, struct tail_call_state);

int tail_call(struct __sk_buff * skb) {

    struct __sk_buff * key = skb;
    struct tail_call_state * state = tail_state.lookup(&key);
    if(state!=NULL && state->tail_call_count < 10){
        bpf_trace_printk("Tail-Call Program %p %u %u\n", key, state->src_port, ++state->tail_call_count);
        // bpf_trace_printk("Tail-Call Program %u %u %u\n", state->src_ip, state->dst_ip, state->dst_port);
        prog_array.call(skb,2);
        goto TAIL_EXIT;
        tail_state.delete(&key);
    }
TAIL_EXIT:
    tail_state.delete(&key);
    return 0;
}

int read_metric(struct __sk_buff * skb) {
    struct __sk_buff * sKey = skb;
    __u8 *cursor = 0;
    struct metric_key mKey = {
        .src_port = 0
    };
    struct metric_data *mData;

    struct ethernet_t * ethernet = cursor_advance(cursor, sizeof(struct ethernet_t));

    struct ip_t * ip = cursor_advance(cursor, sizeof(struct ip_t));
    __u8 ip_header_length = ip->hlen << 2; // Shift Left 2 -> *4 multiply
    if(ip_header_length < sizeof(struct ip_t)){
        goto PACKET_MONITOR_EXIT;
    }
    if(ip->nextp != IP_TCP){
        goto PACKET_MONITOR_EXIT;
    }
   // Shift cursor forward for dynamic header size
    void *_ = cursor_advance(cursor,(ip_header_length - sizeof(struct ip_t)));

    struct tcp_t *tcp = cursor_advance(cursor,sizeof(struct tcp_t));

    mKey.src_port = tcp->src_port;
    mData = user_metric.lookup(&mKey);
    if(mData == NULL){
        goto PACKET_MONITOR_EXIT;
    }

    __u8 tcp_header_length = tcp->offset << 2;
    __u32 payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    __u32 payload_length = ip->tlen - ip_header_length - tcp_header_length;
    __u32 total_length = payload_length + payload_offset;

    if(payload_length <= MIN_HTTP_TLEN){
        goto PACKET_MONITOR_EXIT;
    }
    bpf_trace_printk("Read metric %s %u %u\n", mData->tag, mData->tag_length, mData->tag_lps[2]);

    // struct tail_call_state state = {};
    // state.src_ip = ip->src;
    // state.dst_ip = ip->dst;
    // state.src_port = tcp->src_port;
    // state.dst_port = tcp->dst_port;
    // state.tail_call_count = 1;    
    // tail_state.update(&key,&state);

    // bpf_trace_printk("Original Program %p %u %u\n", key, state.src_port, state.tail_call_count);
    // bpf_trace_printk("Original Program %u %u %u\n", state.src_ip, state.dst_ip, state.dst_port);
    // prog_array.call(skb, 2);
PACKET_MONITOR_EXIT:
    return 0;
}
