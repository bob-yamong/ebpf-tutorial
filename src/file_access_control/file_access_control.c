#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "file_access_control.skel.h"

#define MAX_PATH_LEN 256
#define MAX_CMD_LEN 1024
#define MAX_OUTPUT_LEN 256

struct key_t {
    __u32 ns_id;
    __u64 cgroup_id;
    char filename[MAX_PATH_LEN];
};

typedef enum {
    RUNTIME_UNKNOWN,
    RUNTIME_DOCKER,
    RUNTIME_CONTAINERD,
    RUNTIME_CRIO
} ContainerRuntime;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
    stop = 1;
}

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
            printf("Using Docker runtime\n");
            return get_docker_pid(container_name);
        case RUNTIME_CONTAINERD:
            printf("Using containerd runtime\n");
            return get_containerd_pid(container_name);
        case RUNTIME_CRIO:
            printf("Using CRI-O runtime\n");
            return get_crio_pid(container_name);
        default:
            fprintf(stderr, "Unknown or unsupported container runtime\n");
            return -1;
    }
}

__u32 get_namespace_id(int container_pid) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", container_pid);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open namespace file");
        return 0;
    }

    char link_target[MAX_PATH_LEN];
    ssize_t len = readlink(path, link_target, sizeof(link_target)-1);
    if (len < 0) {
        perror("Failed to read link");
        close(fd);
        return 0;
    }
    link_target[len] = '\0';

    unsigned int ns_id;
    if (sscanf(link_target, "pid:[%u]", &ns_id) != 1) {
        fprintf(stderr, "Failed to parse namespace ID\n");
        close(fd);
        return 0;
    }

    close(fd);
    return (__u32)ns_id;
}

__u64 get_cgroup_id(int container_pid) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", container_pid);
    
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("Failed to open cgroup file");
        return 0;
    }

    char line[256];
    __u64 cgroup_id = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "0::/kubepods/%*[^/]/%llu", &cgroup_id) == 1) {
            break;
        }
    }

    fclose(f);
    return cgroup_id;
}

int block_file(int map_fd, const char *container_name, const char *filename)
{
    struct key_t host_key = {};
    struct key_t container_key = {};
    struct key_t relative_key = {};
    __u8 value = 1;

    int container_pid = get_container_pid(container_name);
    if (container_pid < 0) {
        fprintf(stderr, "Failed to get container PID\n");
        return -1;
    }

    host_key.ns_id = container_key.ns_id = relative_key.ns_id = get_namespace_id(container_pid);
    host_key.cgroup_id = container_key.cgroup_id = relative_key.cgroup_id = get_cgroup_id(container_pid);
    
    // Host full path
    char proc_root[MAX_PATH_LEN];
    snprintf(proc_root, sizeof(proc_root), "/proc/%d/root", container_pid);
    snprintf(host_key.filename, sizeof(host_key.filename), "%s%s", proc_root, filename);

    // Container internal absolute path
    strncpy(container_key.filename, filename, sizeof(container_key.filename) - 1);
    container_key.filename[sizeof(container_key.filename) - 1] = '\0';

    // Relative path
    const char *last_slash = strrchr(filename, '/');
    if (last_slash) {
        strncpy(relative_key.filename, last_slash + 1, sizeof(relative_key.filename) - 1);
    } else {
        strncpy(relative_key.filename, filename, sizeof(relative_key.filename) - 1);
    }
    relative_key.filename[sizeof(relative_key.filename) - 1] = '\0';

    // Add host full path
    if (bpf_map_update_elem(map_fd, &host_key, &value, BPF_ANY)) {
        perror("bpf_map_update_elem (host path)");
        return -1;
    }

    // Add container internal absolute path
    if (bpf_map_update_elem(map_fd, &container_key, &value, BPF_ANY)) {
        perror("bpf_map_update_elem (container path)");
        return -1;
    }

    // Add relative path
    if (bpf_map_update_elem(map_fd, &relative_key, &value, BPF_ANY)) {
        perror("bpf_map_update_elem (relative path)");
        return -1;
    }

    printf("Blocked access to file:\n");
    printf("  Host path: %s\n", host_key.filename);
    printf("  Container path: %s\n", container_key.filename);
    printf("  Relative path: %s\n", relative_key.filename);
    printf("In container: %s (NS ID: %u, Cgroup ID: %llu)\n", 
           container_name, host_key.ns_id, host_key.cgroup_id);
    return 0;
}


int unblock_file(int map_fd, const char *container_name, const char *filename)
{
    struct key_t key = {};

    int container_pid = get_container_pid(container_name);
    if (container_pid < 0) {
        fprintf(stderr, "Failed to get container PID\n");
        return -1;
    }

    key.ns_id = get_namespace_id(container_pid);
    key.cgroup_id = get_cgroup_id(container_pid);
    
    // 컨테이너의 루트 디렉토리 경로 구성
    char container_root[MAX_PATH_LEN];
    snprintf(container_root, sizeof(container_root), "/proc/%d/root", container_pid);

    // 전체 파일 경로 구성
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s%s", container_root, filename);

    // 실제 경로 해석 (심볼릭 링크 등 처리)
    if (realpath(full_path, key.filename) == NULL) {
        // 파일이 존재하지 않는 경우에도 차단 해제 시도
        strncpy(key.filename, full_path, sizeof(key.filename) - 1);
        key.filename[sizeof(key.filename) - 1] = '\0';
    }

    int result = bpf_map_delete_elem(map_fd, &key);
    if (result == 0) {
        printf("Unblocked access to file: %s in container: %s (NS ID: %u, Cgroup ID: %llu)\n", 
               key.filename, container_name, key.ns_id, key.cgroup_id);
        return 0;
    } else if (result == -ENOENT) {
        printf("File was not blocked: %s in container: %s (NS ID: %u, Cgroup ID: %llu)\n", 
               key.filename, container_name, key.ns_id, key.cgroup_id);
        return 0;
    } else {
        perror("bpf_map_delete_elem");
        return -1;
    }
}

void print_blocked_files(int map_fd)
{
    struct key_t key, next_key;
    __u8 value;
    
    printf("Currently blocked files:\n");
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            printf("File: %s, NS ID: %u, Cgroup ID: %llu\n", 
                   next_key.filename, next_key.ns_id, next_key.cgroup_id);
        }
        key = next_key;
    }
}

int main(int argc, char **argv)
{
    struct file_access_control_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    skel = file_access_control_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = file_access_control_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    int map_fd = bpf_map__fd(skel->maps.blocked_files);

    printf("eBPF program is running. Use the following commands:\n");
    printf("  block [container_name] [filename]: Block access to a file in a container\n");
    printf("  unblock [container_name] [filename]: Unblock access to a file in a container\n");
    printf("  list: Block file list\n");
    printf("  quit: Exit the program\n");

    char cmd[256];
    char container_name[64];
    char filename[MAX_PATH_LEN];

    while (!stop) {
        printf("> ");
        if (fgets(cmd, sizeof(cmd), stdin) == NULL) {
            break;
        }
        cmd[strcspn(cmd, "\n")] = 0;  // Remove newline

        if (strncmp(cmd, "block ", 6) == 0) {
            sscanf(cmd, "block %63s %255s", container_name, filename);
            block_file(map_fd, container_name, filename);
        } else if (strncmp(cmd, "unblock ", 8) == 0) {
            sscanf(cmd, "unblock %63s %255s", container_name, filename);
            unblock_file(map_fd, container_name, filename);
        } else if (strcmp(cmd, "quit") == 0) {
            break;
        } else if (strcmp(cmd, "list") == 0) {
            print_blocked_files(map_fd);
        }else {
            printf("Unknown command\n");
        }
    }

    printf("Cleaning up\n");

cleanup:
    file_access_control_bpf__destroy(skel);
    return -err;
}