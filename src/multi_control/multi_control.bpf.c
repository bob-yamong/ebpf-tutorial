#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // ns_id
    __type(value, __u32);
    __uint(max_entries, 10240);
} ns_id_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct syscall_key);
    __type(value, struct syscall_policy);
    __uint(max_entries, 10240);
} syscall_policy_map SEC(".maps");

struct syscall_key {
    __u32 ns_id;
    __u32 event_id;
};

struct syscall_policy {
    __u32 action;
    char argument[256];
};

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/task_fix_setuid")
int BPF_PROG(prevent_root_setuid, struct cred *new, const struct cred *old, int flags) {
    __u32 ns_id, pid;
    __u32 new_uid, old_uid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_core_read(&new_uid, sizeof(new_uid), &new->uid.val);
    bpf_core_read(&old_uid, sizeof(old_uid), &old->uid.val);

    __u32 *watched = bpf_map_lookup_elem(&ns_id_map, &ns_id);

    bpf_printk("lsm/task_fix_setuid for ns_id %u, pid %u, new uid: %u, old uid: %u", ns_id, pid, new_uid, old_uid);

    if (watched && new_uid == 0) {
        bpf_printk("Prevented root escalation for watched ns_id %u", ns_id);
        return -1;
    }

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(prevent_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    __u32 ns_id, pid;
    struct syscall_key key = {0};
    struct syscall_policy *policy;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    pid = bpf_get_current_pid_tgid() >> 32;

    key.ns_id = ns_id;
    key.event_id = 1;

    policy = bpf_map_lookup_elem(&syscall_policy_map, &key);
    if (policy) {
        if (address->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)address;
            __be32 dst_ip;
            __be16 dst_port;

            bpf_probe_read(&dst_ip, sizeof(dst_ip), &addr->sin_addr.s_addr);
            bpf_probe_read(&dst_port, sizeof(dst_port), &addr->sin_port);

            __be32 blocked_ip;
            bpf_probe_read(&blocked_ip, sizeof(blocked_ip), policy->argument);
            if (policy->action == 1) {
                if (dst_ip == blocked_ip) {
                    bpf_printk("Connection blocked to IP: %pI4 for ns_id %u\n", &dst_ip, ns_id);
                    return -1;
                }
                return 0;
            }else if (policy->action == 0) {
                if (dst_ip == blocked_ip) {
                    bpf_printk("Connection allowed to IP: %pI4 for ns_id %u\n", &dst_ip, ns_id);
                    return 0;
                }
                return -1;
            }
        }
    }

    return 0;
}