#include <net/sock.h>

BPF_PROG_ARRAY(prog_array, 10);
BPF_HASH(tail_state, struct __sk_buff *);

int tail_call(struct __sk_buff * skb) {
    u64 *datap = tail_state.lookup(&skb),data;
    if(datap!=NULL){
        tail_state.delete(&skb);
        bpf_trace_printk("Tail-call %d\n", data);
        prog_array.call(skb,2);
    }
    return 0;
}

int do_tail_call(struct __sk_buff * skb) {
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
    if (tcp->src_port != PORT_TO_MONITOR)
        goto EXIT;

    u64 data = 1;
    tail_state.update(&skb,&data);
    bpf_trace_printk("Original program %d\n", data);
    prog_array.call(skb, 2);
    return 0;
}
