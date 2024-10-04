// file_access_control.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256

struct key_t {
    __u32 ns_id;
    char filename[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key_t);
    __type(value, __u8);
} blocked_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct key_t);
} temp_key SEC(".maps");

static __always_inline int check_blocked(struct key_t *key) {
    __u8 *blocked = bpf_map_lookup_elem(&blocked_files, key);
    bpf_printk("Checking file: %s, NS ID: %u, Blocked: %d\n", 
                key->filename, key->ns_id, (blocked ? *blocked : 0));
    return (blocked && *blocked == 1);
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file) {
    __u32 zero = 0;
    struct key_t *key = bpf_map_lookup_elem(&temp_key, &zero);
    if (!key)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    key->ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

    if (bpf_d_path(&file->f_path, key->filename, sizeof(key->filename)) < 0) {
        bpf_printk("Failed to get file path");
        return 0;
    }

    // Check both host and container paths
    bpf_printk("Checking file: %s, NS ID: %u", key->filename, key->ns_id);

    // Check if the file is blocked in the host
    if (check_blocked(key)) {
        bpf_printk("Blocking access to file (host path): %s", key->filename);
        return -1;
    }

    // Check the file path in the container context
    char *container_path = key->filename;
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN - 6; i++) {
        if (key->filename[i] == '\0')
            break;
        if (key->filename[i] == '/' && key->filename[i+1] == 'r' &&
            key->filename[i+2] == 'o' && key->filename[i+3] == 'o' &&
            key->filename[i+4] == 't' && key->filename[i+5] == '/') {
            container_path = &key->filename[i+6];
            break;
        }
    }

    struct key_t container_key = *key;
    bpf_probe_read_str(container_key.filename, sizeof(container_key.filename), container_path);

    // Check if the file is blocked for the container
    if (check_blocked(&container_key)) {
        bpf_printk("Blocking access to file (container path): %s", container_key.filename);
        return -1;
    }
    struct task_struct *parent_task = BPF_CORE_READ(task, parent);
    container_key.ns_id = BPF_CORE_READ(parent_task, nsproxy, pid_ns_for_children, ns.inum);
    bpf_printk("Checking file: %s, NS ID: %u", container_key.filename, container_key.ns_id);
    if (check_blocked(&container_key)) {
        bpf_printk("Blocking access to file (container path): %s", container_key.filename);
        return -1;
    }

    bpf_printk("Allowing access to file: %s", key->filename);
    return 0;
}


char LICENSE[] SEC("license") = "GPL";