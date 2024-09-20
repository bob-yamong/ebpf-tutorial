#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // pid
    __type(value, __u32);
    __uint(max_entries, 1024);
} ns_id_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/task_fix_setuid")
int BPF_PROG(prevent_root_setuid, struct cred *new, const struct cred *old, int flags) {
    __u32 ns_id;
    __u32 pid;
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
// bpf_core_read(&dst, size, src)에서 dst는 데이터를 저장할 변수, size는 읽을 데이터의 크기, src는 읽을 커널 구조체의 필드

// struct task_struct *task;
// struct nsproxy *nsproxy;
// struct pid_namespace *pid_ns;
// bpf_core_read(&nsproxy, sizeof(nsproxy), &task->nsproxy);
// bpf_core_read(&pid_ns, sizeof(pid_ns), &nsproxy->pid_ns_for_children);
// bpf_core_read(&ns_id, sizeof(ns_id), &pid_ns->ns.inum);