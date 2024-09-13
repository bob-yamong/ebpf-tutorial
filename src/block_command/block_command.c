#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "block_command.skel.h"

static volatile bool exiting = false;

static void handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("PID %d (Parent PID: %d) [%s] tried to execute %s: Blocked\n",
           e->pid, e->ppid, e->comm, e->filename);
}

void handle_signal(int sig) {
    exiting = true;
}

void print_help() {
    printf("Commands:\n");
    printf("  add_allow <path>       - Add allowed program path\n");
    printf("  remove_allow <path>    - Remove allowed program path\n");
    printf("  add_block_parent <name>    - Add blocked parent process name\n");
    printf("  remove_block_parent <name> - Remove blocked parent process name\n");
    printf("  list_allow             - List allowed program paths\n");
    printf("  list_block_parent      - List blocked parent process names\n");
    printf("  exit                   - Exit the program\n");
}

int main(int argc, char **argv) {
    struct block_command_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    char command[512];
    __u8 value = 0;

    // 시그널 핸들러 설정
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // eBPF 스켈레톤 로드 및 검증
    skel = block_command_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load eBPF skeleton\n");
        return 1;
    }

    // eBPF 프로그램 어태치
    err = block_command_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        goto cleanup;
    }

    // 링 버퍼 설정
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Monitoring execve calls... Type 'help' for commands. Press Ctrl+C or type 'exit' to quit.\n");

    // 이벤트 수신 및 명령 처리 루프
    while (!exiting) {
        // 비차단 방식으로 링 버퍼 폴링
        err = ring_buffer__poll(rb, 0);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
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
                printf("Path is too long.\n");
                continue;
            }
            err = bpf_map_update_elem(bpf_map__fd(skel->maps.allowed_programs), path, &value, BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to add allowed program: %d\n", err);
            } else {
                printf("Added allowed program: %s\n", path);
            }
        } else if (strncmp(command, "remove_allow ", 13) == 0) {
            char *path = command + 13;
            if (strlen(path) >= 256) {
                printf("Path is too long.\n");
                continue;
            }
            err = bpf_map_delete_elem(bpf_map__fd(skel->maps.allowed_programs), path);
            if (err) {
                fprintf(stderr, "Failed to remove allowed program: %d\n", err);
            } else {
                printf("Removed allowed program: %s\n", path);
            }
        } else if (strncmp(command, "add_block_parent ", 17) == 0) {
            char *name = command + 17;
            if (strlen(name) >= TASK_COMM_LEN) {
                printf("Process name is too long.\n");
                continue;
            }
            err = bpf_map_update_elem(bpf_map__fd(skel->maps.blocked_parents), name, &value, BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to add blocked parent: %d\n", err);
            } else {
                printf("Added blocked parent: %s\n", name);
            }
        } else if (strncmp(command, "remove_block_parent ", 20) == 0) {
            char *name = command + 20;
            if (strlen(name) >= TASK_COMM_LEN) {
                printf("Process name is too long.\n");
                continue;
            }
            err = bpf_map_delete_elem(bpf_map__fd(skel->maps.blocked_parents), name);
            if (err) {
                fprintf(stderr, "Failed to remove blocked parent: %d\n", err);
            } else {
                printf("Removed blocked parent: %s\n", name);
            }
        } else if (strcmp(command, "list_allow") == 0) {
            // 화이트리스트 목록 출력 (구현 간단화를 위해 생략)
            printf("Listing allowed programs is not implemented.\n");
        } else if (strcmp(command, "list_block_parent") == 0) {
            // 차단할 부모 프로세스 목록 출력 (구현 간단화를 위해 생략)
            printf("Listing blocked parents is not implemented.\n");
        } else if (strcmp(command, "exit") == 0) {
            exiting = true;
        } else if (strlen(command) == 0) {
            // 아무 입력도 없을 때 무시
            continue;
        } else {
            printf("Unknown command: %s\n", command);
            print_help();
        }
    }

cleanup:
    ring_buffer__free(rb);
    block_command_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
