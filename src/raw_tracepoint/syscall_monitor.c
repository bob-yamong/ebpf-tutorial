#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "syscall_monitor.skel.h"

static volatile bool exiting = false;

void handle_signal(int sig) {
    exiting = true;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct syscall_event *event = data;
    printf("PID %d: 시스템 콜 번호 %u 호출\n", event->pid, event->syscall_nr);
    // 필요한 경우 인자 출력 등 추가 처리
}

void lost_event(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "이벤트 손실 발생: %llu개\n", lost_cnt);
}

int main(int argc, char **argv) {
    struct syscall_monitor_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

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
        fprintf(stderr, "eBPF 프로그램 어태치 실패\n");
        goto cleanup;
    }

    // perf_buffer 설정
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, lost_event, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "perf_buffer 생성 실패\n");
        goto cleanup;
    }

    printf("시스템 콜 모니터링을 시작합니다...\n");

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "perf_buffer__poll() 오류: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    syscall_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
