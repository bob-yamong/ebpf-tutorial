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
#include <sqlite3.h>
#include "sqlite_multi_control.skel.h"

#define MAX_PATH 256



struct event_key {
    __u32 ns_id;
    __u32 event_id;
    char argument[256];
};

#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256

typedef enum {
    RUNTIME_UNKNOWN,
    RUNTIME_DOCKER,
    RUNTIME_CONTAINERD,
    RUNTIME_CRIO
} ContainerRuntime;

ContainerRuntime get_runtime_from_user() {
    char input[20];
    printf("Enter container runtime (docker/containerd/crio): ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return RUNTIME_UNKNOWN;
    }
    input[strcspn(input, "\n")] = 0;

    if (strcmp(input, "docker") == 0) return RUNTIME_DOCKER;
    if (strcmp(input, "containerd") == 0) return RUNTIME_CONTAINERD;
    if (strcmp(input, "crio") == 0) return RUNTIME_CRIO;
    
    return RUNTIME_UNKNOWN;
}

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

// 여러개 가능, 현재는 name으로 찾지만 label, namespace 구현 필요
int get_containerd_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "ctr task ls | awk '$1 == \"%s\" {print $2}'", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to run ctr task info command");
        return -1;
    }
    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    output[strcspn(output, "\n")] = 0;

    return atoi(output);
}

// 여러개 가능, 현재는 name인데 사실 pod임 추가로 label, namespace 구현 필요
int get_crio_pid(const char* container_name) {
    char cmd[MAX_CMD_LEN];
    char output[MAX_OUTPUT_LEN];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "crictl inspect $(crictl ps | grep \"\\b%s\\b\" | awk '{print $1}') 2>/dev/null | grep -Po '\"pid\":\\s*\\K[0-9]+'", container_name);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("Failed to run crictl inspect command");
        return -1;
    }

    if (fgets(output, sizeof(output), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    output[strcspn(output, "\n")] = 0;

    return atoi(output);
}

int get_container_pid(const char* container_name) {
    ContainerRuntime runtime = get_runtime_from_user();
    
    switch(runtime) {
        case RUNTIME_DOCKER:
            printf("docker\n");
            return get_docker_pid(container_name);
        case RUNTIME_CONTAINERD:
            printf("containerd\n");
            return get_containerd_pid(container_name);
        case RUNTIME_CRIO:
            printf("cri-o\n");
            return get_crio_pid(container_name);
        default:
            fprintf(stderr, "Unknown or unsupported container runtime\n");
            return -1;
    }
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

void apply_policies_from_db(struct multi_control_bpf *skel, sqlite3 *db) {
    // container_runtime, container_name, event_id, argument, action
    // container_runtime 0: docker, 1: containerd, 2: crio
    // container_name example: ldap_ssh_container
    // event_id 0: lsm/task_fix_setuid 1:lsm/socket_connect
    // argument example: 1.1.1.1
    // action 0: allow, 1: deny
    const char *sql = "SELECT container_runtime, container_name, event_id, argument, action FROM policies";
    int rc;
    int policy_count = 0;
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        struct event_key key = {0};
        __u32 action;
        __u32 container_runtime = sqlite3_column_int(stmt, 0);
        key.ns_id = sqlite3_column_int(stmt, 0);
        key.event_id = sqlite3_column_int(stmt, 1);
        strncpy(key.argument, (const char *)sqlite3_column_text(stmt, 2), sizeof(key.argument) - 1);
        action = strcmp((const char *)sqlite3_column_text(stmt, 3), "allow") == 0 ? 0 : 1;

        if (bpf_map__update_elem(skel->maps.event_policy_map, &key, sizeof(key), &action, sizeof(action), BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update BPF map\n");
        } else {
            policy_count++;
        }
    }

    sqlite3_finalize(stmt);
    printf("Applied %d policies from the database.\n", policy_count);
}

int main(int argc, char **argv) {
    int err;
    sqlite3 *db;

    
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
    // SQLite3 데이터베이스 열기
    err = sqlite3_open("policy.db", &db);
    if (err) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    

    // 15초마다 정책을 다시 불러와 적용
    while (1) {
        apply_policies_from_db(skel, db);
        sleep(15);
    }

cleanup:
    multi_control_bpf__destroy(skel);
    sqlite3_close(db);
    return err != 0;
}