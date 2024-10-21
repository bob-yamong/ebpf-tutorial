#include <bpf/libbpf.h>
#include "poc.skel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

#define MAX_GROUPS 5
#define MAX_CGROUPS 10
#define MAX_PERMISSIONS 5

struct cgroup_permissions {
    __u8 socket_create;
    __u8 execute;
};

struct group_policy {
    __u64 cgroup_ids[MAX_CGROUPS];
    struct cgroup_permissions permissions[MAX_CGROUPS];
};

struct policy_event {
    __u32 uid;
    __u64 cgroup_id;
    __u32 action;
    __u32 operation;
};

void input_user_groups(__u32 *uid, __u32 groups[MAX_GROUPS]) {
    printf("Enter user ID: ");
    scanf("%u", uid);

    printf("Enter up to %d group IDs for this user (enter 0 to finish):\n", MAX_GROUPS);
    for (int i = 0; i < MAX_GROUPS; i++) {
        scanf("%u", &groups[i]);
        if (groups[i] == 0) break;
    }
}

void input_group_policy(__u32 *group_id, struct group_policy *policy) {
    printf("Enter group ID: ");
    scanf("%u", group_id);

    printf("Enter up to %d cgroup IDs and their permissions (enter 0 for cgroup ID to finish):\n", MAX_CGROUPS);
    for (int i = 0; i < MAX_CGROUPS; i++) {
        printf("Enter cgroup ID: ");
        scanf("%llu", &policy->cgroup_ids[i]);
        if (policy->cgroup_ids[i] == 0) break;

        printf("Enter permissions for cgroup %llu (1 for yes, 0 for no):\n", policy->cgroup_ids[i]);
        printf("Socket Create: ");
        scanf("%hhu", &policy->permissions[i].socket_create);
        printf("Execute: ");
        scanf("%hhu", &policy->permissions[i].execute);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct policy_event *e = data;
    printf("UID: %u, CGroup ID: %llu, Action: %s, Operation: %s\n",
           e->uid, e->cgroup_id,
           e->action == 1 ? "Allowed" : (e->action == 0 ? "Denied" : "Debug"),
           e->operation ? "Execute" : "Socket Connect");
    return 0;
}

int main(int argc, char **argv) {
    struct poc_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    skel = poc_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = poc_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "BPF 스켈레톤을 연결하는데 실패했습니다: %d\n", err);
        goto cleanup;
    }

    // 사용자-그룹 맵 초기화
    __u32 uid;
    __u32 groups[MAX_GROUPS] = {0};
    input_user_groups(&uid, groups);

    err = bpf_map__update_elem(skel->maps.user_group_map, &uid, sizeof(uid), groups, sizeof(groups), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update user_group_map\n");
        goto cleanup;
    }

    // 그룹 정책 맵 초기화
    __u32 group_id;
    struct group_policy policy = {0};
    input_group_policy(&group_id, &policy);

    err = bpf_map__update_elem(skel->maps.group_policy_map, &group_id, sizeof(group_id), &policy, sizeof(policy), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update group_policy_map\n");
        goto cleanup;
    }

    printf("Maps initialized successfully.\n");

    // 여기에 프로그램의 메인 로직을 추가합니다.

    // Ring buffer 설정
    rb = ring_buffer__new(bpf_map__fd(skel->maps.policy_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Listening for events...\n");
    while (1) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    poc_bpf__destroy(skel);
    return err < 0 ? err : 0;
}
