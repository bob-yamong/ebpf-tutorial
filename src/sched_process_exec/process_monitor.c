#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>  // For u32
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>       // For va_list
#include "process_monitor.skel.h"

#define TASK_COMM_LEN 16

static volatile bool exiting = false;\

struct event {
    char comm[TASK_COMM_LEN];  // Process name (comm)
    __u32 pid;                 // Process ID
};

static void sig_handler(int sig) {
    exiting = true;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args) {
    // Adjust logging based on level if necessary
    return vfprintf(stderr, fmt, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("Process created: %s (PID: %d)\n", e->comm, e->pid);
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct process_monitor_bpf *skel; // Ensure this matches your actual type
    char target_comm[TASK_COMM_LEN] = {};
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <process_name>\n", argv[0]);
        return 1;
    }

    strncpy(target_comm, argv[1], TASK_COMM_LEN - 1);

    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);

    // Open BPF application
    skel = process_monitor_bpf__open(); // Ensure this function name matches
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = process_monitor_bpf__load(skel); // Ensure this function name matches
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attach tracepoint
    err = process_monitor_bpf__attach(skel); // Ensure this function name matches
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    // Set the target process name in the BPF map
    __u32 key = 0; // Define key properly
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.target_comm_map), &key, target_comm, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update BPF map with target process name\n");
        goto cleanup;
    }

    // Set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // Handle signals for graceful termination
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Monitoring for process: %s\n", target_comm);
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    // Clean up
    ring_buffer__free(rb);
    process_monitor_bpf__destroy(skel); // Ensure this function name matches

    return err < 0 ? -err : 0;
}
