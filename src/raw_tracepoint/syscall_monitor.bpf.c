#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct syscall_event {
    __u32 pid;
    __u32 syscall_nr;
    __u64 args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// 시스템 콜 진입점 모니터링
SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    struct syscall_event event = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    event.pid = pid;
    event.syscall_nr = ctx->args[0];

    // 시스템 콜 인자 저장
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        event.args[i] = ctx->args[i + 1];
    }

    // 이벤트 전송
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}
