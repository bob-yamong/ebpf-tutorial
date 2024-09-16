#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // pid
    __type(value, __u32);
    __uint(max_entries, 1024);
} pid_map SEC(".maps");

// 이건 그냥 자격 증명 때 호출되는 lsm hook 이었음
// SEC("lsm/cred_prepare")
// int BPF_PROG(prevent_root, struct cred *new, const struct cred *old, gfp_t gfp) {
//     __u32 pid = bpf_get_current_pid_tgid() >> 32;
//     __u32 *watched = bpf_map_lookup_elem(&pid_map, &pid);

//     bpf_printk("lsm/cred_prepare for pid %d, new uid: %d, old uid: %d", pid, new->uid.val, old->uid.val);

//     if (watched && new->uid.val == 0) {
//         bpf_printk("Prevented root escalation for pid %d\n", pid);
//         return -1;
//     }

//     if (new->uid.val == 0 && old->uid.val != 0) {
//         bpf_printk("Prevented root escalation for pid %d\n", pid);
//         return -1;
//     }

//     return 0;
// }

SEC("lsm/task_fix_setuid")
int BPF_PROG(prevent_root_setuid, struct cred *new, const struct cred *old, int flags) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *watched = bpf_map_lookup_elem(&pid_map, &pid);

    bpf_printk("lsm/task_fix_setuid for pid %d, new uid: %d, old uid: %d", 
               pid, new->uid.val, old->uid.val);

    if (watched && new->uid.val == 0) {
        bpf_printk("Prevented root escalation for watched pid %d", pid);
        return -1;
    }

    // if (new->uid.val == 0 && old->uid.val != 0) {
    //     bpf_printk("Prevented global root escalation for pid %d", pid);
    //     return -1;
    // }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";