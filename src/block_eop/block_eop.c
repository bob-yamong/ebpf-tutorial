#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "block_eop.skel.h"

int main(int argc, char **argv) {
    struct block_eop_bpf *skel;
    int err;

    skel = block_eop_bpf__open(); // Ensure this function name matches
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = block_eop_bpf__load(skel); // Ensure this function name matches
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = block_eop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // main loop process from user's input
    while (1) {
        char pid_str[256];
        __u32 pid;
        __u32 value = 1;

        printf("Enter pid name to restrict (or 'quit' to exit): ");
        if (fgets(pid_str, sizeof(pid_str), stdin) == NULL) {
            break;
        }
        pid_str[strcspn(pid_str, "\n")] = 0;

        // quit program
        if (strcmp(pid_str, "quit") == 0) {
            break;
        }

        pid = (__u32)atoi(pid_str);

        // update eBPF map
        err = bpf_map__update_elem(skel->maps.pid_map, &pid, sizeof(pid), &value, sizeof(value), BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update map: %d\n", err);
            continue;
        }

        printf("Now restricting root access in pid: %s\n", pid_str);
    }

cleanup:
    block_eop_bpf__destroy(skel);
    return err != 0;
}