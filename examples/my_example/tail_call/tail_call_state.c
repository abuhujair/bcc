#include <bcc/proto.h>
#include <net/sock.h>

#define IP_TCP 6

BPF_PROG_ARRAY(prog_array, 10);

struct tail_call_state{
    u32 src_ip;
    u32 dst_ip;
    u32 src_port;
    u32 dst_port;
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

int do_tail_call(struct __sk_buff * skb) {
    struct __sk_buff * key = skb;
    __u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(struct ethernet_t));
    struct ip_t *ip = cursor_advance(cursor, sizeof(struct ip_t));
    __u32 ip_header_length = ip->hlen << 2; // Shift left 2 -> *4 multiply
    if (ip_header_length < sizeof(struct ip_t)){
        goto EXIT;
    }
    if (ip->nextp != IP_TCP){
        goto EXIT;
    }
    // shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length - sizeof(struct ip_t)));
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(struct tcp_t));

    struct tail_call_state state = {};
    state.src_ip = ip->src;
    state.dst_ip = ip->dst;
    state.src_port = tcp->src_port;
    state.dst_port = tcp->dst_port;
    state.tail_call_count = 1;
    
    tail_state.update(&key,&state);
    bpf_trace_printk("Original Program %p %u %u\n", key, state.src_port, state.tail_call_count);
    // bpf_trace_printk("Original Program %u %u %u\n", state.src_ip, state.dst_ip, state.dst_port);
    prog_array.call(skb, 2);
EXIT:
    return 0;
}
