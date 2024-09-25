#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "multi_control.skel.h"

#define MAX_PATH 256

struct syscall_key {
    __u32 ns_id;
    __u32 event_id;
};

struct syscall_policy {
    __u32 action;
    char argument[256];
};

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
    struct multi_control_bpf *skel;
    int err;

    skel = multi_control_bpf__open(); // Ensure this function name matches
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = multi_control_bpf__load(skel); // Ensure this function name matches
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = multi_control_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // main loop process from user's input
    while (1) {
        char pid_str[256];
        char event_str[256];
        char ip_str[16];
        char action_str[10];
        __u32 pid;
        __u32 value;    // 무의미한 값
        __u32 ns_id;
        __u32 event_id;
        __u32 action;

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
        
        printf("Enter event (e.g., task_fix_setuid, socket_connect): ");
        if (fgets(event_str, sizeof(event_str), stdin) == NULL) {
            break;
        }
        event_str[strcspn(event_str, "\n")] = 0;

        if (strcmp(event_str, "task_fix_setuid") == 0) {
            event_id = 0;
            err = bpf_map__update_elem(skel->maps.ns_id_map, &ns_id, sizeof(ns_id), &value, sizeof(value), BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to update map: %d\n", err);
                continue;
            }

            printf("Now restricting root access in pid: %s\n", pid_str);
        } else if (strcmp(event_str, "socket_connect") == 0) {
            event_id = 1;
            printf("Enter IP to block or allow (e.g., 8.8.8.8): ");
            if (fgets(ip_str, sizeof(ip_str), stdin) == NULL) {
                break;
            }
            ip_str[strcspn(ip_str, "\n")] = 0;

            struct in_addr ip_addr;
            if (inet_pton(AF_INET, ip_str, &ip_addr) != 1) {
                fprintf(stderr, "ERROR: Invalid IP address\n");
                continue;
            }

            printf("Enter action to block or allow (e.g., block, allow): ");
            if (fgets(action_str, sizeof(action_str), stdin) == NULL) {
                break;
            }
            action_str[strcspn(action_str, "\n")] = 0;

            if (strcmp(action_str, "allow") == 0) action = 0;
            if (strcmp(action_str, "block") == 0) action = 1;

            struct syscall_key key = {
                .ns_id = ns_id,
                .event_id = event_id
            };

            struct syscall_policy policy = {
                .action = action
            };
            memcpy(policy.argument, &ip_addr.s_addr, sizeof(ip_addr.s_addr));

            err = bpf_map__update_elem(skel->maps.syscall_policy_map, &key, sizeof(key), &policy, sizeof(policy), BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to update map: %d\n", err);
                continue;
            }

            printf("Now restricting ip/port(%s) access in pid: %s\n", ip_str, pid_str);
        }
    }

cleanup:
    multi_control_bpf__destroy(skel);
    return err != 0;
}