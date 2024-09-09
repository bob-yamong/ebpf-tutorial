#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800 // 이더넷 프로토콜 번호 직접 정의

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} filtered_ips SEC(".maps");

struct ip_log {
    __u32 src_ip;
    __u32 dest_ip;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("xdp")
int xdp_ip_logger(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    bpf_printk("test1 \n");
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end){ 
        return XDP_PASS;
    }
    
    if (eth->h_proto != __bpf_htons(ETH_P_IP)){
        return XDP_PASS;
    }
        

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end){
        return XDP_PASS;
    }

    __u8 *value = bpf_map_lookup_elem(&filtered_ips, &ip->saddr);
    if (!value)
        return XDP_PASS;

    struct ip_log *log = bpf_ringbuf_reserve(&rb, sizeof(struct ip_log), 0);
    if (!log){
        return XDP_PASS;
    }
        

    log->src_ip = ip->saddr;
    log->dest_ip = ip->daddr;
    log->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(log, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
