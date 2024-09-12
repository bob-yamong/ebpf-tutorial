#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <linux/limits.h>
#include "check_path.skel.h"

// Define the 'event' structure
struct event {
    char filename[256];
    char isBlocked;
};


static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = (struct event *)data;
    printf("File accessed %s: %s\n", e->isBlocked? "Block": "Allow",e->filename);
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct check_path_bpf *skel;
    int err;

    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);

    // Cleaner handling of Ctrl-C
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load BPF skeleton
    skel = check_path_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = check_path_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attach the BPF program to the tracepoint
    err = check_path_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    // Set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // Poll ring buffer for events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    // Clean up
    ring_buffer__free(rb);
    check_path_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
