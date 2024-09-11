#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>  // For task_struct
#include <linux/ptrace.h>
#include <linux/string.h>

#define TASK_COMM_LEN 16

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, char[TASK_COMM_LEN]);
    __uint(max_entries, 1);  // We track only one process name
} target_comm_map SEC(".maps");

struct event {
    char comm[TASK_COMM_LEN];  // Process name (comm)
    __u32 pid;                 // Process ID
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // Adjust ring buffer size as needed
} events SEC(".maps");

static __always_inline int compare_strings(const char *a, const char *b, __u32 len) {
    for (__u32 i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return 0;  // Not equal
        }
        if (a[i] == '\0') {
            return 1;  // Equal
        }
    }
    return 1;  // Equal if both strings are of length `len` and match
}

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(void *ctx) {
    char target_comm[TASK_COMM_LEN] = {};
    char comm[TASK_COMM_LEN] = {};
    struct event *e;
    __u32 key = 0;  // Key used for lookups

    // Get the process name of the newly created process
    bpf_get_current_comm(&comm, sizeof(comm));

    // Fetch the target process name from the map
    char *stored_comm = bpf_map_lookup_elem(&target_comm_map, &key);
    if (stored_comm == NULL) {
        return 0;
    }

    __builtin_memcpy(target_comm, stored_comm, TASK_COMM_LEN);

    // If the process name matches the target, log it
    if (compare_strings(comm, target_comm, TASK_COMM_LEN)) {
        e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!e) {
            return 0;
        }

        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->pid = bpf_get_current_pid_tgid() >> 32;

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
