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
    char argument[256];
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


SEC("lsm/task_fix_setuid")
int BPF_PROG(prevent_root_setuid, struct cred *new, const struct cred *old, int flags) {
    __u32 ns_id, pid, cgroup_id;
    __u32 new_uid, old_uid;
    __u32 event_id = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    cgroup_id = get_cgroup_id();

    char cgroup_name[64];
    get_cgroup_name(cgroup_name, sizeof(cgroup_name));

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_core_read(&new_uid, sizeof(new_uid), &new->uid.val);
    bpf_core_read(&old_uid, sizeof(old_uid), &old->uid.val);

    struct event_key key = {
        .ns_id = ns_id,
        .event_id = event_id,
        // argument is not used for this event, so we don't need to set it
    };

    __u32 *watched = bpf_map_lookup_elem(&event_policy_map, &key);

    bpf_printk("lsm/task_fix_setuid for ns_id %u, pid %u, new uid: %u, old uid: %u", ns_id, pid, new_uid, old_uid);

    if (watched && new_uid == 0) {
        bpf_printk("Prevented root escalation for watched ns_id %u", ns_id);
        return -1;
    }

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(prevent_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    __u32 ns_id;
    __u32 event_id = 1;
    struct event_key key = {0};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    if (address->sa_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)address;
        __be32 dst_ip;
        __be16 dst_port;

        bpf_probe_read(&dst_ip, sizeof(dst_ip), &addr->sin_addr.s_addr);
        bpf_probe_read(&dst_port, sizeof(dst_port), &addr->sin_port);

        key.ns_id = ns_id;
        key.event_id = event_id;
        bpf_probe_read(&key.argument, sizeof(__be32), &dst_ip);

        __u32 *mode = bpf_map_lookup_elem(&event_mode_map, &event_id);
        __u32 *policy = bpf_map_lookup_elem(&event_policy_map, &key);

        if (mode) {
            if (*mode == 0) {    // Allow
                if (policy && *policy == 0) {  // ip in key
                    bpf_printk("Connection allowed to IP: %pI4 for ns_id %u\n", &dst_ip, ns_id);
                    return 0;
                }
                bpf_printk("Connection blocked (not in allowlist) to IP: %pI4 for ns_id %u\n", &dst_ip, ns_id);
                return -1;
            } else if (*mode == 1) { // Block
                if (policy && *policy == 1) {  // ip in key
                    bpf_printk("Connection allowed to IP: %pI4 for ns_id %u\n", &dst_ip, ns_id);
                    return -1;
                }
                bpf_printk("Connection allowed (not in blocklist) to IP: %pI4 for ns_id %u\n", &dst_ip, ns_id);
                return 0;
            }
        }
    }
    return 0;
}
