#include <vmlinux.h>
#include <linux/limits.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TARGET_DIR "/home/test"
#define TARGET_DIR_LEN (sizeof(TARGET_DIR) - 1)

// BPF ring buffer (used to communicate events to user space)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB size
} events SEC(".maps");

// Monitoring file event structure
struct event {
    char filename[PATH_MAX];
    char isBlocked;
};

struct sys_enter_openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

static int my_bpf_strncmp(const char *s1, const char *s2, int n) {
    while (n-- && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (n + 1) ? *(unsigned char *)s1 - *(unsigned char *)s2 : 0;
}

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

// tracepoint: sys_enter_openat 훅을 설치하여 파일 열기 시점 추적
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_monitor_directory_access(struct sys_enter_openat_args *ctx) {
    const char *filename = NULL;
    struct event *e;

    // Reserve memory for event in ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Read filename from the kernel memory
    bpf_probe_read(&filename, sizeof(filename), &ctx->filename);
    bpf_probe_read_str(&e->filename, sizeof(e->filename), filename);

    // Check if the file path matches the target directory
    if (compare_strings(e->filename, TARGET_DIR, TARGET_DIR_LEN)) {
        // Block execution
        e->isBlocked = 1;
    } else {
        e->isBlocked = 0;  // Allow access
    }

    // Submit event to user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}


// License declaration
char LICENSE[] SEC("license") = "GPL";
