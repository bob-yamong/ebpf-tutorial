// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 1024

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_pids SEC(".maps");

static __always_inline __u64 get_cgroup_id() {
    struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return 0;
    }

    int mem_cgrp_id = memory_cgrp_id;

    __u64 cgroup_id = BPF_CORE_READ(cur_tsk, cgroups, subsys[mem_cgrp_id], cgroup, kn, id);

    return cgroup_id;
}

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 ppid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u32 *blocked = bpf_map_lookup_elem(&blocked_pids, &ppid);

    int ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    u64 cgroup_id = get_cgroup_id();

    if (blocked && *blocked == 1) {
        bpf_printk("Task creation blocked for CGroup ID: %llu, PID %d(%d), NS: %llu", cgroup_id, ppid, pid, ns);
        return -1;
    }

    blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    if (blocked && *blocked == 1) {
        bpf_printk("Task creation blocked for CGroup ID: %llu, PID %d(%d), NS: %llu", cgroup_id, ppid, pid, ns);
        return -1;
    }

    bpf_printk("Task creation allowed for CGroup ID: %llu, PID %d(%d), NS: %llu", cgroup_id, ppid, pid, ns);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";