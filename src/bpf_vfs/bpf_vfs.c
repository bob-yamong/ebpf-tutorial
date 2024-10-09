#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf_vfs.skel.h"

#define BPF_FS_PATH "/sys/fs/bpf"
#define MAP_PIN_PATH "/sys/fs/bpf/blocked_pids"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct bpf_vfs_bpf *skel;
    int err, map_fd;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Try to open existing pinned map */
    map_fd = bpf_obj_get(MAP_PIN_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "No existing map found, creating a new one.\n");
    } else {
        fprintf(stderr, "Found existing map, reusing it.\n");
    }

    /* Open BPF application */
    skel = bpf_vfs_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* If we found an existing map, use it instead of creating a new one */
    if (map_fd >= 0) {
        bpf_map__set_pin_path(skel->maps.blocked_pids, MAP_PIN_PATH);
        err = bpf_map__reuse_fd(skel->maps.blocked_pids, map_fd);
        if (err) {
            fprintf(stderr, "Failed to reuse existing map: %d\n", err);
            goto cleanup;
        }
    }

    /* Load & verify BPF programs */
    err = bpf_vfs_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = bpf_vfs_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Pin the map to BPF filesystem if it wasn't already pinned */
    if (map_fd < 0) {
        err = bpf_object__pin_maps(skel->obj, BPF_FS_PATH);
        if (err) {
            fprintf(stderr, "Failed to pin maps: %d\n", err);
            goto cleanup;
        }
    }

    /* Open the pinned map (or reuse the fd if we already have it) */
    if (map_fd < 0) {
        map_fd = bpf_obj_get(MAP_PIN_PATH);
        if (map_fd < 0) {
            fprintf(stderr, "Failed to open pinned map: %s\n", strerror(errno));
            goto cleanup;
        }
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
            if (bpf_map_update_elem(map_fd, &pid, &value, BPF_ANY)) {
                fprintf(stderr, "Failed to block PID %d: %s\n", pid, strerror(errno));
            } else {
                printf("Blocked task creation for PID %d\n", pid);
            }
        } else if (sscanf(cmd, "unblock %d", &pid) == 1) {
            if (bpf_map_delete_elem(map_fd, &pid)) {
                fprintf(stderr, "Failed to unblock PID %d: %s\n", pid, strerror(errno));
            } else {
                printf("Unblocked task creation for PID %d\n", pid);
            }
        } else if (strcmp(cmd, "list") == 0) {
            unsigned int key = 0, next_key;
            unsigned int value;

            while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
                if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
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
    /* We don't unpin the map here, so it persists after the program exits */
    bpf_vfs_bpf__destroy(skel);
    return -err;
}