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
#include "container_manage.skel.h"

#define MAX_PATH 256

struct event_key {
    __u32 ns_id;
    __u32 event_id;
    char argument[64];
};

#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256

int get_docker_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "docker inspect -f '{{.State.Pid}}' %s", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to run docker command");
        return -1;
    }

    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    return atoi(output);
}

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
    struct container_manage_bpf *skel;
    int err;

    skel = container_manage_bpf__open(); // Ensure this function name matches
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = container_manage_bpf__load(skel); // Ensure this function name matches
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = container_manage_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // main loop process from user's input
    char ip_str[16];
    __u32 pid;
    __u32 ns_id;
    __u32 event_id;
    __u32 action;


    do {
        printf("Enter IP to block or allow (e.g., 8.8.8.8): ");
    
        action = 1;
        
        fgets(ip_str, sizeof(ip_str), stdin);
        ip_str[strcspn(ip_str, "\n")] = 0;

        struct in_addr ip_addr;
        if (inet_pton(AF_INET, ip_str, &ip_addr) != 1) {
            fprintf(stderr, "ERROR: Invalid IP address\n");
        }

        FILE *file = fopen("container_list.txt", "r");
        if (file == NULL) {
            perror("Error opening file");
            return EXIT_FAILURE;
        }

        char line[256]; // Buffer to hold each line
        while (fgets(line, sizeof(line), file)) {
            printf("%s", line); // Print each line
            pid = get_docker_pid(line);
            ns_id = get_namespace_id(pid);
            event_id = 1;

            struct event_key key = {
                .ns_id = ns_id,
                .event_id = event_id
            };
            memcpy(key.argument, &ip_addr.s_addr, sizeof(ip_addr.s_addr));

            err = bpf_map__update_elem(skel->maps.event_mode_map, &event_id, sizeof(event_id), &action, sizeof(action), BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to update map: %d\n", err);
                continue;
            }
            err = bpf_map__update_elem(skel->maps.event_policy_map, &key, sizeof(key), &action, sizeof(action), BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to update map: %d\n", err);
                continue;
            }
            
        }

        fclose(file);

        while(1){
            char a = getchar();
            if (a == 'e') exit(0);
            if (a == 'n'){
                fflush(stdin);
                while (getchar() != '\n') continue;
                break;
            }
        }
    } while(1);


cleanup:
    container_manage_bpf__destroy(skel);
    return err != 0;
}