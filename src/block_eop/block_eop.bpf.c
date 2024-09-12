#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);   // cgroup ID
    __type(value, u32);
    __uint(max_entries, 1024);
} cgroup_map SEC(".maps");

SEC("lsm/cred_prepare")
int BPF_PROG(prevent_root, struct cred *new, const struct cred *old, gfp_t gfp) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u32 *watched = bpf_map_lookup_elem(&cgroup_map, &cgroup_id);

    if (watched && new->uid.val == 0) {
        bpf_printk("Prevented root escalation for cgroup ID %llu\n", cgroup_id);
        return -1;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";