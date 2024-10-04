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
} blocked_pids SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    u32 *blocked = bpf_map_lookup_elem(&blocked_pids, &ppid);

    if (blocked && *blocked == 1) {
        bpf_printk("Task creation blocked for parent PID %d", ppid);
        return -1;
    }

    bpf_printk("Task creation allowed for parent PID %d", ppid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";