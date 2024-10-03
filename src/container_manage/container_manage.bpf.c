#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // event_id
    __type(value, __u32); // allow or block
    __uint(max_entries, 10240);
} event_mode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct event_key);
    __type(value, __u32);   // action
    __uint(max_entries, 10240);
} event_policy_map SEC(".maps");

struct event_key {
    __u32 ns_id;
    __u32 event_id;
    char argument[64];
};

static __always_inline __u64 get_cgroup_id() {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return 0;
    }

    int mem_cgrp_id = memory_cgrp_id;

    __u64 cgroup_id = BPF_CORE_READ(cur_tsk, cgroups, subsys[mem_cgrp_id], cgroup, kn, id);
    bpf_printk("cgroup_id: %llu\n", cgroup_id);

    return cgroup_id;
}

static __always_inline int get_cgroup_name(char *buf, size_t sz) {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return -1;
    }

    int cgrp_id = memory_cgrp_id;


    // failed when use BPF_PROBE_READ
    const char *name = BPF_CORE_READ(cur_tsk, cgroups, subsys[cgrp_id], cgroup, kn, name);
    // bpf_printk("name: %s\n", name);
    if (bpf_probe_read_kernel_str(buf, sz, name) < 0) {
        bpf_printk("failed to get kernfs node name: %s\n", buf);
        return -1;
    }
    bpf_printk("cgroup name: %s\n", buf);

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(prevent_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    __u32 ns_id;
    __u32 event_id = 1;
    struct event_key key_src = {0};
    struct event_key key_dst = {0};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    if (address->sa_family == AF_INET) {
        // Destination IP and port (from address argument)
        struct sockaddr_in *addr = (struct sockaddr_in *)address;
        __be32 dst_ip;
        __be16 dst_port;
        bpf_probe_read(&dst_ip, sizeof(dst_ip), &addr->sin_addr.s_addr);
        bpf_probe_read(&dst_port, sizeof(dst_port), &addr->sin_port);

        // Source IP and port (from socket structure)
        if (sock) return 0;
        struct sock *sk = sock->sk;
        __be32 src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);

        // Add src_ip and dst_ip to event_key for checking policies
        key_dst.ns_id = ns_id;
        key_dst.event_id = event_id;
        bpf_probe_read(&key_dst.argument, sizeof(__be32), &dst_ip);  // Storing destination IP in argument field

        key_src.ns_id = ns_id;
        key_src.event_id = event_id;
        bpf_probe_read(&key_src.argument, sizeof(__be32), &src_ip);  // Storing source IP in argument field

        // Map lookup for event mode and policy for src and dst
        __u32 *mode = bpf_map_lookup_elem(&event_mode_map, &event_id);
        __u32 *policy_src = bpf_map_lookup_elem(&event_policy_map, &key_src);
        __u32 *policy_dst = bpf_map_lookup_elem(&event_policy_map, &key_dst);

        // Check if the mode is set
        if (mode) {
            if (*mode == 0) {    // Allow mode
                // Check if the source or destination IP matches the allowlist
                if ((policy_src && *policy_src == 0) || (policy_dst && *policy_dst == 0)) {
                    bpf_printk("Connection allowed to IP: %pI4 from IP: %pI4 for ns_id %u\n", &dst_ip, &src_ip, ns_id);
                    return 0;
                }
                // If not in allowlist, block
                bpf_printk("Connection blocked (not in allowlist) to IP: %pI4 from IP: %pI4 for ns_id %u\n", &dst_ip, &src_ip, ns_id);
                return -1;
            } else if (*mode == 1) { // Block mode
                // Check if the source or destination IP matches the blocklist
                if ((policy_src && *policy_src == 1) || (policy_dst && *policy_dst == 1)) {
                    bpf_printk("Connection blocked to IP: %pI4 from IP: %pI4 for ns_id %u\n", &dst_ip, &src_ip, ns_id);
                    return -1;
                }
                // If not in blocklist, allow
                bpf_printk("Connection allowed (not in blocklist) to IP: %pI4 from IP: %pI4 for ns_id %u\n", &dst_ip, &src_ip, ns_id);
                return 0;
            }
        }
    }
    return 0;
}