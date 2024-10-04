// file_access_control.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256

struct key_t {
    __u32 ns_id;
    __u64 cgroup_id;
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
    return (blocked && *blocked == 1);
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
    __u32 zero = 0;
    struct key_t *key = bpf_map_lookup_elem(&temp_key, &zero);
    if (!key) 
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    key->ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key->cgroup_id = bpf_get_current_cgroup_id();
    
    if (bpf_d_path(&file->f_path, key->filename, sizeof(key->filename)) < 0) {
        bpf_printk("Failed to get file path");
        return 0;
    }
    
    bpf_printk("Checking file: %s, NS ID: %u, Cgroup ID: %llu", key->filename, key->ns_id, key->cgroup_id);
    
    // Check host full path
    if (check_blocked(key)) {
        bpf_printk("Blocking access to file (host path): %s", key->filename);
        return -1;
    }
    
    // Check container internal path and relative path
    char *path_start = key->filename;
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN - 6; i++) {
        if (key->filename[i] == '\0')
            break;
        if (key->filename[i] == '/' && key->filename[i+1] == 'r' &&
            key->filename[i+2] == 'o' && key->filename[i+3] == 'o' && 
            key->filename[i+4] == 't' && key->filename[i+5] == '/') {
            path_start = &key->filename[i+6];
            break;
        }
    }
    
    struct key_t check_key = *key;
    bpf_probe_read_str(check_key.filename, sizeof(check_key.filename), path_start);
    
    if (check_blocked(&check_key)) {
        bpf_printk("Blocking access to file (container/relative path): %s", check_key.filename);
        return -1;
    }
    
    bpf_printk("Allowing access to file: %s", key->filename);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";