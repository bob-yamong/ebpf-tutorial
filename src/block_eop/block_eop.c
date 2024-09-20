#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "block_eop.skel.h"

#define MAX_PATH 256

int get_namespace_id(int container_pid) {
    
    // PID 네임스페이스 ID 찾기
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", container_pid);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open namespace file");
        return 1;
    }

    char link_target[MAX_PATH];
    ssize_t len = readlink(path, link_target, sizeof(link_target)-1);
    if (len < 0) {
        perror("Failed to read link");
        close(fd);
        return 1;
    }
    link_target[len] = '\0';

    unsigned int ns_id;
    if (sscanf(link_target, "pid:[%u]", &ns_id) != 1) {
        fprintf(stderr, "Failed to parse namespace ID\n");
        close(fd);
        return 1;
    }

    printf("PID namespace ID for PID %d: %u\n", container_pid, ns_id);

    close(fd);
    return ns_id;
}

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
        __u32 value;    // 무의미한 값
        __u32 ns_id;

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
        ns_id = get_namespace_id(pid);

        // update eBPF map
        err = bpf_map__update_elem(skel->maps.ns_id_map, &ns_id, sizeof(ns_id), &value, sizeof(value), BPF_ANY);
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