#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TARGET_DIR "/home/test"
#define TARGET_DIR_LEN (sizeof(TARGET_DIR) - 1)

enum action{
    ALLOW = 0,
    BLOCK = 1,
};

// BPF ring buffer (used to communicate events to user space)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB size
} events SEC(".maps");

// Monitoring file event structure
struct event {
    char filename[256];
    char isBlocked;
};

// sys_enter_openat tracepoint에 맞는 구조체 정의
struct sys_enter_openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    unsigned char filename[256];
    long flags;
    long mode;
};

// Custom strncmp function for BPF
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


// Tracepoint for sys_enter_openat hook to track file open events
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_monitor_directory_access(struct sys_enter_openat_args *ctx) {
    const char *filename = NULL;
    struct event *e;

    // Reserve memory for event in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->isBlocked = 0;

    // Read filename from the kernel memory
    bpf_probe_read(&filename, sizeof(filename), &ctx->filename);
    bpf_probe_read_str(&e->filename, sizeof(e->filename), filename);

    // Check if the file path matches the target directory
    if (!compare_strings(e->filename, TARGET_DIR, TARGET_DIR_LEN)) 
        e->isBlocked = 1;

    // Submit event to user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// LSM hook for file_open
SEC("lsm/file_open")
// int lsm_monitor_directory_access(struct file *file, const struct cred *cred, struct inode *inode) {
int lsm_monitor_directory_access(struct file *file) {
    struct event *e;

    // Reserve memory for event in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Get the file path
    bpf_probe_read_str(e->filename, sizeof(e->filename), file->f_path.dentry->d_name.name);

    // Compare the file path with TARGET_DIR
    if (compare_strings(e->filename, TARGET_DIR, TARGET_DIR_LEN) == 0) {
        e->isBlocked = 1;
        bpf_ringbuf_submit(e, 0);
        return -1; // Block access
    }

    e->isBlocked = 0;
    bpf_ringbuf_submit(e, 0);
    return 0; // Allow access
}


// License declaration
char LICENSE[] SEC("license") = "GPL";
