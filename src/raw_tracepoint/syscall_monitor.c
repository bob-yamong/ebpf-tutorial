// syscall_monitor.c

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h> // va_list를 사용하기 위한 헤더 추가
#include <bpf/libbpf.h>
#include "syscall_monitor.skel.h"

static volatile bool exiting = false;

// libbpf 디버그 출력 함수 정의
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

void handle_signal(int sig) {
    exiting = true;
}

// eBPF 프로그램과 동일한 구조체 정의
struct syscall_event {
    __u32 pid;
    __u32 syscall_nr;
    __u64 args[6];
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct syscall_event *event = data;
    printf("PID %d: 시스템 콜 번호 %u 호출\n", event->pid, event->syscall_nr);
    return 0;
}

int main(int argc, char **argv) {
    struct syscall_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // libbpf 디버그 출력 활성화
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // eBPF 스켈레톤 로드 및 검증
    skel = syscall_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "eBPF 스켈레톤 로드 실패\n");
        return 1;
    }

    // eBPF 프로그램 어태치
    err = syscall_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "eBPF 프로그램 어태치 실패: %d\n", err);
        goto cleanup;
    }

    // Ring Buffer 설정
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Ring Buffer 생성 실패\n");
        err = 1;
        goto cleanup;
    }

    printf("시스템 콜 모니터링을 시작합니다...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll() 오류: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    syscall_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
