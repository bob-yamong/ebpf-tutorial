#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <linux/types.h>  // __u32 등을 사용하기 위해 필요
#include <bpf/libbpf.h>
#include "block_command.skel.h"

#define TASK_COMM_LEN 16

static volatile bool exiting = false;

// eBPF 프로그램과 동일한 구조체 정의
struct event {
    __u32 pid;
    __u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char action;  // 1: 차단, 0: 허용
} __attribute__((packed));

// 이벤트 핸들러 함수
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("PID %d (부모 PID: %d) [%s]가 %s 실행 시도: 차단됨\n",
           e->pid, e->ppid, e->comm, e->filename);
    return 0;
}

// 시그널 핸들러
void handle_signal(int sig) {
    exiting = true;
}

// 도움말 출력 함수
void print_help() {
    printf("명령어:\n");
    printf("  add_allow <path>       - 허용된 프로그램 경로 추가\n");
    printf("  remove_allow <path>    - 허용된 프로그램 경로 제거\n");
    printf("  add_block_parent <name>    - 차단할 부모 프로세스 이름 추가\n");
    printf("  remove_block_parent <name> - 차단할 부모 프로세스 이름 제거\n");
    printf("  list_allow             - 허용된 프로그램 경로 목록\n");
    printf("  list_block_parent      - 차단할 부모 프로세스 이름 목록\n");
    printf("  exit                   - 프로그램 종료\n");
}

int main(int argc, char **argv) {
    struct block_command_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    char command[512];

    // 시그널 핸들러 설정
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // eBPF 스켈레톤 로드 및 검증
    skel = block_command_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "eBPF 스켈레톤을 열고 로드하는 데 실패했습니다\n");
        return 1;
    }

    // eBPF 프로그램 어태치
    err = block_command_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "eBPF 프로그램을 어태치하는 데 실패했습니다\n");
        goto cleanup;
    }

    // 링 버퍼 설정
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "링 버퍼를 생성하는 데 실패했습니다\n");
        err = 1;
        goto cleanup;
    }

    printf("execve 호출을 모니터링합니다... 명령어 목록은 'help'를 입력하세요. Ctrl+C 또는 'exit'를 입력하여 종료합니다.\n");

    // 이벤트 수신 및 명령 처리 루프
    while (!exiting) {
        // 비차단 방식으로 링 버퍼 폴링
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "링 버퍼 폴링 중 오류 발생: %d\n", err);
            break;
        }

        // 사용자 입력 처리
        printf("> ");
        fflush(stdout);
        if (!fgets(command, sizeof(command), stdin)) {
            break;
        }

        // 개행 문자 제거
        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "help") == 0) {
            print_help();
        } else if (strncmp(command, "add_allow ", 10) == 0) {
            char *path = command + 10;
            if (strlen(path) >= 256) {
                printf("경로가 너무 깁니다.\n");
                continue;
            }
            char key[256] = {0};
            strncpy(key, path, sizeof(key) - 1);
            __u8 value = 0;
            err = bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_programs),
                                      key, &value, BPF_ANY);
            if (err) {
                fprintf(stderr, "허용된 프로그램을 추가하는 데 실패했습니다: %d\n", err);
            } else {
                printf("허용된 프로그램 추가: %s\n", path);
            }
        } else if (strncmp(command, "remove_allow ", 13) == 0) {
            char *path = command + 13;
            if (strlen(path) >= 256) {
                printf("경로가 너무 깁니다.\n");
                continue;
            }
            char key[256] = {0};
            strncpy(key, path, sizeof(key) - 1);
            err = bpf_map_delete_elem(bpf_map__fd(skel->maps.allowed_programs), key);
            if (err) {
                fprintf(stderr, "허용된 프로그램을 제거하는 데 실패했습니다: %d\n", err);
            } else {
                printf("허용된 프로그램 제거: %s\n", path);
            }
        } else if (strncmp(command, "add_block_parent ", 17) == 0) {
            char *name = command + 17;
            if (strlen(name) >= TASK_COMM_LEN) {
                printf("프로세스 이름이 너무 깁니다.\n");
                continue;
            }
            char key[TASK_COMM_LEN] = {0};
            strncpy(key, name, sizeof(key) - 1);
            __u8 value = 0;
            err = bpf_map_update_elem(bpf_map__fd(skel->maps.blocked_parents),
                                      key, &value, BPF_ANY);
            if (err) {
                fprintf(stderr, "차단할 부모 프로세스를 추가하는 데 실패했습니다: %d\n", err);
            } else {
                printf("차단할 부모 프로세스 추가: %s\n", name);
            }
        } else if (strncmp(command, "remove_block_parent ", 20) == 0) {
            char *name = command + 20;
            if (strlen(name) >= TASK_COMM_LEN) {
                printf("프로세스 이름이 너무 깁니다.\n");
                continue;
            }
            char key[TASK_COMM_LEN] = {0};
            strncpy(key, name, sizeof(key) - 1);
            err = bpf_map_delete_elem(bpf_map__fd(skel->maps.blocked_parents), key);
            if (err) {
                fprintf(stderr, "차단할 부모 프로세스를 제거하는 데 실패했습니다: %d\n", err);
            } else {
                printf("차단할 부모 프로세스 제거: %s\n", name);
            }
        } else if (strcmp(command, "list_allow") == 0) {
            // 허용된 프로그램 목록 출력 (구현 생략)
            printf("허용된 프로그램 목록 출력은 구현되지 않았습니다.\n");
        } else if (strcmp(command, "list_block_parent") == 0) {
            // 차단할 부모 프로세스 목록 출력 (구현 생략)
            printf("차단할 부모 프로세스 목록 출력은 구현되지 않았습니다.\n");
        } else if (strcmp(command, "exit") == 0) {
            exiting = true;
        } else if (strlen(command) == 0) {
            // 아무 입력도 없을 때 무시
            continue;
        } else {
            printf("알 수 없는 명령어: %s\n", command);
            print_help();
        }
    }

cleanup:
    ring_buffer__free(rb);
    block_command_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
