# Issue
- `bprm_check_security` LSM 훅에서 `bprm->filename`에 접근하려고 할 때 접근 거부 발생
- BPF 검증기는 LSM 훅에서 특정 구조체의 포인터 필드에 대한 접근을 제한
- `struct linux_binprm`의 `filename` 필드는 LSM 훅에서 BPF 프로그램이 직접 접근할 수 없는 필드
