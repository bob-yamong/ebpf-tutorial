#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_CGROUPS 10
#define MAX_PERMISSIONS 5

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u32[5]);
} user_group_map SEC(".maps");

struct cgroup_permissions {
    __u8 socket_create;
    __u8 execute;
};

struct group_policy {
    __u64 cgroup_ids[MAX_CGROUPS];
    struct cgroup_permissions permissions[MAX_CGROUPS];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, struct group_policy);
} group_policy_map SEC(".maps");

struct policy_event {
    __u32 uid;
    __u64 cgroup_id;
    __u32 action;  // 0: 거부, 1: 허용
    __u32 operation;  // 0: socket_connect, 1: bprm_check_security
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} policy_events SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct policy_event *event;
    event = bpf_ringbuf_reserve(&policy_events, sizeof(*event), 0);
    if (!event) {
        return 0;  // ��벤트를 기록할 수 없으면 기본적으로 허용
    }

    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->operation = 0;  // socket_connect
    event->action = 2;  // 디버그 표시

    bpf_printk("uid: %u, cgroup_id: %llu", event->uid, event->cgroup_id);

    __u32 *groups = bpf_map_lookup_elem(&user_group_map, &event->uid);
    
    if (!groups) {
        event->action = 1; 
        bpf_ringbuf_submit(event, 0);
        return 0;
    }

    if(event->cgroup_id != 43659 || event->cgroup_id != 43859) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // 사용자의 각 그룹에 대해 권한 확인
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        __u32 group_id = groups[i];
        if (group_id == 0) break;  // 그룹 ID가 0이면 더 이상 유효한 그룹이 없음

        struct group_policy *policy = bpf_map_lookup_elem(&group_policy_map, &group_id);
        if (!policy) continue;  // 이 그룹에 대한 정책이 없으면 다음 그룹으로

        #pragma unroll
        for (int j = 0; j < MAX_CGROUPS; j++) {
            if (policy->cgroup_ids[j] == event->cgroup_id) {
                // cgroup_id에 대한 권한이 있음
                // socket_create 권한 확인
                if (policy->permissions[j].socket_create) {
                    event->action = 1;  // 허용
                    bpf_ringbuf_submit(event, 0);
                    bpf_printk("socket_create allowed");
                    return 0;  // 권한 있음, 연결 허용
                }
                break;  // 이 cgroup에 대한 권한은 찾았지만 socket_create 권한이 없음
            }
        }
    }

    // 어떤 그룹에서도 현재 cgroup에 대한 socket_create 권한을 찾지 못함
    event->action = 0;  // 거부
    bpf_ringbuf_submit(event, 0);
    return -1;  // 권한 없음, 연결 거부
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
{
    struct policy_event *event;
    event = bpf_ringbuf_reserve(&policy_events, sizeof(*event), 0);
    if (!event) {
        return 0;  // 이벤트를 기록할 수 없으면 기본적으로 허용
    }

    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->operation = 1;  // bprm_check_security
    event->action = 2;  // 디버그 표시

    __u32 *groups = bpf_map_lookup_elem(&user_group_map, &event->uid);
    __u64 cgroup_id = event->cgroup_id;

    if (!groups) {
        event->action = 1; 
        bpf_ringbuf_submit(event, 0);
        return 0;
    }

    if(event->cgroup_id != 43659 || event->cgroup_id != 43859) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // 사용자의 각 그룹에 대해 권한 확인
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        __u32 group_id = 0;
        if (groups) {
            group_id = groups[i];
        }
        if (group_id == 0) break;  // 그룹 ID가 0이면 더 이상 유효한 그룹이 없음

        struct group_policy *policy = bpf_map_lookup_elem(&group_policy_map, &group_id);
        if (!policy) continue;  // 이 그룹에 대한 정책이 없으면 다음 그룹으로

        // 현재 cgroup_id에 대한 권한 확인
        #pragma unroll
        for (int j = 0; j < MAX_CGROUPS; j++) {
            if (policy->cgroup_ids[j] == cgroup_id) {
                // cgroup_id에 대한 권한이 있음
                // sudo 권한 확인
                if (policy->permissions[j].execute) {
                    event->action = 1;  // 허용
                    bpf_ringbuf_submit(event, 0);
                    return 0;  // 권한 있음, 실행 허용
                }
                break;  // 이 cgroup에 대한 권한은 찾았지만 sudo 권한이 없음
            }
        }
    }

    // 어떤 그룹에서도 현재 cgroup에 대한 sudo 권한을 찾지 못함
    event->action = 0;  // 거부
    bpf_ringbuf_submit(event, 0);
    return -1;  // 권한 없음, 실행 거부
}
