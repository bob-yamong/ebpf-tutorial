#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <linux/types.h>
#include "block_eop.skel.h"

#include <dirent.h>

#define MAX_PATH_LEN 256

// // Function to get cgroup ID from container name/ID (simplified)
// __u64 get_cgroup_id_from_container(const char *container_name) {
//     // In a real implementation, you would use Docker API or read from
//     // /sys/fs/cgroup to get the cgroup ID for the given container name
//     // This is a placeholder function
//     return 0;  // Replace with actual implementation
// }

__u64 get_cgroup_id_from_container(const char *container_name) {
    char cgroup_path[MAX_PATH_LEN];
    FILE *file;
    char buffer[256];

    // 컨테이너의 PID를 알아야 함. 여기에선 컨테이너 이름을 PID로 변환하는 과정을 생략함.
    // 예시로 컨테이너의 PID가 12345라고 가정
    int pid = 12345;

    // /proc/<pid>/cgroup 파일에서 cgroup 경로를 읽음
    snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%d/cgroup", pid);

    file = fopen(cgroup_path, "r");
    if (!file) {
        perror("fopen");
        return 0;
    }

    // /proc/<pid>/cgroup 파일을 읽고 해당 cgroup ID를 추출
    while (fgets(buffer, sizeof(buffer), file)) {
        if (strstr(buffer, "memory")) {  // 메모리 서브 시스템을 기준으로 함
            // cgroup 경로에서 ID를 추출하는 로직 추가 필요
            // 여기서는 간단히 경로를 출력하는 예시
            printf("Cgroup info: %s", buffer);
        }
    }

    fclose(file);
    return 0;  // 실제 cgroup ID를 추출하여 반환하는 로직을 추가
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
    // // Load and attach BPF program
    // skel = block_eop_bpf__open_and_load();
    // if (!skel) {
    //     fprintf(stderr, "Failed to open and load BPF skeleton\n");
    //     return 1;
    // }

    err = block_eop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // main loop process from user's input
    while (1) {
        char container_name[256];
        __u64 cgroup_id;
        __u32 value = 1;

        // get container name from user
        printf("Enter container name to restrict (or 'quit' to exit): ");
        if (fgets(container_name, sizeof(container_name), stdin) == NULL) {
            break;
        }
        container_name[strcspn(container_name, "\n")] = 0;  // Remove newline

        // quit는 종료
        if (strcmp(container_name, "quit") == 0) {
            break;
        }

        // get cgroup id from container name
        cgroup_id = get_cgroup_id_from_container(container_name);
        if (cgroup_id == 0) {
            fprintf(stderr, "Failed to get cgroup ID for container %s\n", container_name);
            continue;
        }

        // update eBPF map
        err = bpf_map_update_elem(skel->maps.cgroup_map, &cgroup_id, sizeof(cgroup_id), &value, sizeof(value), BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update map: %d\n", err);
            continue;
        }

        printf("Now restricting root access in container: %s\n", container_name);
    }

cleanup:
    block_eop_bpf__destroy(skel);
    return err != 0;
}