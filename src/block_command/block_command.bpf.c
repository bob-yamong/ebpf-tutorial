#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define EACCES 13  // Permission denied

// 이벤트 구조체 정의
struct event {
    __u32 pid;
    __u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char action;  // 1: 차단, 0: 허용
} __attribute__((packed));

// BPF 링 버퍼 (유저 공간과 이벤트를 전달하기 위해 사용)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB 크기
} events SEC(".maps");

// 허용할 프로그램 경로를 저장하는 BPF 해시 맵 (화이트리스트)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[256]);  // 프로그램 경로
    __type(value, __u8);     // 임의의 값
    __uint(max_entries, 1024);
} allowed_programs SEC(".maps");

// 차단할 부모 프로세스 이름을 저장하는 BPF 해시 맵
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[TASK_COMM_LEN]);  // 부모 프로세스 이름
    __type(value, __u8);               // 임의의 값
    __uint(max_entries, 1024);
} blocked_parents SEC(".maps");

// 커널 문자열을 사용자 공간 버퍼로 복사하는 함수
static __always_inline int copy_path(char *dest, const struct path *path, int buf_size) {
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct vfsmount *mnt = BPF_CORE_READ(path, mnt);
    struct qstr d_name;
    const unsigned char *name;
    char slash = '/';
    int pos = buf_size - 1;  // 문자열 끝에 null 문자 위치
    dest[pos] = '\0';
    pos--;

#pragma unroll
    for (int i = 0; i < 64; i++) {
        struct dentry *mnt_root = BPF_CORE_READ(mnt, mnt_root);
        if (dentry == mnt_root) {
            break;
        }
        d_name = BPF_CORE_READ(dentry, d_name);
        int len = d_name.len;
        name = d_name.name;

        if (pos < len + 1) {
            return -1;  // 버퍼 오버플로우 방지
        }
        // 이름 복사
        pos -= len;
        bpf_probe_read_kernel(&dest[pos], len, name);
        // 슬래시 추가
        pos--;
        dest[pos] = slash;
        // 상위 디렉토리로 이동
        dentry = BPF_CORE_READ(dentry, d_parent);
    }

    // 최종 경로 복사
    int copied = buf_size - pos - 1;
#pragma unroll
    for (int i = 0; i < 256; i++) {
        if (i >= copied)
            break;
        dest[i] = dest[pos + i];
    }
    return 0;
}

// 부모 프로세스의 이름과 PID를 가져오는 함수
static __always_inline int get_parent_info(struct task_struct *task, char *comm, __u32 *ppid) {
    struct task_struct *parent_task;
    const char *parent_comm_ptr;
    int ret;

    parent_task = BPF_CORE_READ(task, real_parent);
    *ppid = BPF_CORE_READ(parent_task, tgid);

    // 부모 프로세스의 comm 필드를 먼저 읽어옵니다.
    parent_comm_ptr = BPF_CORE_READ(parent_task, comm);

    // 읽어온 포인터를 사용하여 문자열을 복사합니다.
    ret = bpf_probe_read_kernel_str(comm, TASK_COMM_LEN, parent_comm_ptr);

    return ret;
}

// LSM 훅: 프로세스 실행 전에 호출됨
SEC("lsm/bprm_check_security")
int block_execve(struct linux_binprm *bprm) {
    struct event *e;
    int ret;
    struct task_struct *task;
    __u8 *value;
    char parent_comm[TASK_COMM_LEN];
    __u32 ppid;
    char filepath[256];

    // 실행 파일의 전체 경로 가져오기
    struct file *file = NULL;
    BPF_CORE_READ_INTO(&file, bprm, file);
    if (!file) {
        return 0;
    }
    struct path f_path;
    BPF_CORE_READ_INTO(&f_path, file, f_path);
    ret = copy_path(filepath, &f_path, sizeof(filepath));
    if (ret < 0) {
        return 0;  // 경로를 가져오지 못하면 차단하지 않음
    }

    // 허용된 프로그램인지 확인
    value = bpf_map_lookup_elem(&allowed_programs, filepath);
    if (value) {
        // 화이트리스트에 있음 - 실행 허용
        return 0;
    }

    // 현재 프로세스의 부모 정보 가져오기
    task = (struct task_struct *)bpf_get_current_task();
    ret = get_parent_info(task, parent_comm, &ppid);
    if (ret < 0) {
        // 부모 프로세스 이름을 가져오지 못하면 차단하지 않음
        return 0;
    }

    // 차단할 부모 프로세스인지 확인
    value = bpf_map_lookup_elem(&blocked_parents, parent_comm);
    if (!value) {
        // 차단 대상 아님 - 실행 허용
        return 0;
    }

    // 이벤트를 위한 링 버퍼 메모리 예약
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        // 현재 프로세스 정보 저장
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->ppid = ppid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        // 실행 파일 경로를 이벤트 구조체에 저장
        bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), filepath);

        e->action = 1;  // 차단
        bpf_ringbuf_submit(e, 0);
    }

    return -EACCES;  // 실행 차단
}

// 라이선스 선언
char LICENSE[] SEC("license") = "GPL";
