#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "task_creation_control.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct task_creation_control_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = task_creation_control_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = task_creation_control_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = task_creation_control_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Use the following commands:\n");
    printf("block <pid>   - Block task creation for the specified PID\n");
    printf("unblock <pid> - Unblock task creation for the specified PID\n");
    printf("list          - List all blocked PIDs\n");
    printf("quit          - Exit the program\n");

    while (1) {
        char cmd[256];
        int pid;

        printf("> ");
        if (!fgets(cmd, sizeof(cmd), stdin)) {
            break;
        }
        cmd[strcspn(cmd, "\n")] = 0;

        if (sscanf(cmd, "block %d", &pid) == 1) {
            unsigned int value = 1;
            if (bpf_map_update_elem(bpf_map__fd(skel->maps.blocked_pids), &pid, &value, BPF_ANY)) {
                fprintf(stderr, "Failed to block PID %d: %s\n", pid, strerror(errno));
            } else {
                printf("Blocked task creation for PID %d\n", pid);
            }
        } else if (sscanf(cmd, "unblock %d", &pid) == 1) {
            if (bpf_map_delete_elem(bpf_map__fd(skel->maps.blocked_pids), &pid)) {
                fprintf(stderr, "Failed to unblock PID %d: %s\n", pid, strerror(errno));
            } else {
                printf("Unblocked task creation for PID %d\n", pid);
            }
        } else if (strcmp(cmd, "list") == 0) {
            unsigned int key = 0, next_key;
            unsigned int value;

            while (bpf_map_get_next_key(bpf_map__fd(skel->maps.blocked_pids), &key, &next_key) == 0) {
                if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.blocked_pids), &next_key, &value) == 0) {
                    printf("Blocked PID: %u\n", next_key);
                }
                key = next_key;
            }
        } else if (strcmp(cmd, "quit") == 0) {
            break;
        } else {
            fprintf(stderr, "Unknown command\n");
        }
    }

cleanup:
    task_creation_control_bpf__destroy(skel);
    return -err;
}