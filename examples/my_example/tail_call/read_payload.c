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

#define PAYLOAD_LENGTH 1500
struct payload_t{
    __u8 data[PAYLOAD_LENGTH];
};

// MAP to store state in between tail_call

int read_metric(struct __sk_buff * skb) {
    __u8 *data = (void *)(long)skb->data;
    __u8 *data_end = (void *)(long)skb->data_end;
    // Ethernet Header Parsing
    struct ethernet_t * ethernet = data;
    
    // IP Header Parsing
    struct ip_t * ip = data + ETH_HLEN;
    __u8 ip_header_length = ip->hlen << 2; // Shift Left 2 -> *4 multiply
    if(ip_header_length < sizeof(struct ip_t) || ip->tlen < 1600){
        goto TCP_PARSER_EXIT;
    }
    if(ip->nextp != IP_TCP){
        goto TCP_PARSER_EXIT;
    }
    // Shift cursor forward for dynamic header size
    // void *_ = cursor_advance(cursor,(ip_header_length - sizeof(struct ip_t)));

    // TCP Header Parsing
    struct tcp_t *tcp = data + ETH_HLEN + ip_header_length;
    if(tcp->src_port != PORT_TO_MONITOR || tcp->flag_syn || tcp->flag_fin){
        goto TCP_PARSER_EXIT;
    }
    __u8 tcp_header_length = tcp->offset << 2;
    
    __u16 payload_length = ip->tlen - ip_header_length - tcp_header_length;

    struct payload_t *payload = data + ETH_HLEN + ip_header_length + tcp_header_length;

    if(data+ETH_HLEN+ip_header_length+tcp_header_length+sizeof(struct payload_t) < data_end)    
        bpf_trace_printk("%x",payload->data[0]);
TCP_PARSER_EXIT:
    return 0;
}
