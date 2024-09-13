#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "capture_ip_packet.skel.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
 
struct ip_log {
    __u32 src_ip;
    __u32 dest_ip;
    __u64 timestamp;
};

void print_info() {
    printf("[1] update ip   [2] print log\n");
    printf("enter 'u' or 'U' you can update ip maps\n");
    printf("enter 'l' or 'L' you can print ip log\n");
    printf("enter 'x' or 'X' you can exit ip log viewer\n");
}

static volatile bool exiting = false;
static const char *ifname = "ens38";  // 인터페이스 이름, 입력 받거나 동적으로 가져오는 부분 추가 해야함 

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct ip_log *log = data;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &log->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &log->dest_ip, dst, sizeof(dst));

    printf("IP Packet: %s -> %s at %llu ns\n", src, dst, log->timestamp);
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct capture_ip_packet_bpf *skel;
    int err, ifindex;
    char n;
    int log_flag = 0;

    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    

    char input[INET_ADDRSTRLEN];  // Buffer for IP address input
    __u32 ip_addr;  // IP address in network byte order
    __u8 dummy_value = 1;  // Dummy value for hash map

    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);

    // Cleaner handling of Ctrl-C
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = capture_ip_packet_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = capture_ip_packet_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 인터페이스 인덱스를 가져오기
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        goto cleanup;
    }

    // XDP 프로그램을 인터페이스에 부착
    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_ip_logger), XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    while (!exiting) {
        if (!log_flag) {

            print_info();
            scanf(" %c", &n);

            if (n == 'u' || n == 'U') {
                printf("Enter IP address to filter: ");
                if (scanf("%s", input) == 1) {
                    if (inet_pton(AF_INET, input, &ip_addr) != 1) {
                        fprintf(stderr, "Invalid IP address format\n");
                    } else {
                        // Add IP address to the BPF map
                        if (bpf_map_update_elem(bpf_map__fd(skel->maps.filtered_ips), &ip_addr, &dummy_value, BPF_ANY) != 0) {
                            fprintf(stderr, "Failed to add IP address to the map\n");
                        }
                    }
                }
            } else if (n == 'l' || n == 'L') {
                log_flag = 1;
            } else if (n == 'x' || n == 'X') {
                log_flag = 0;
            } else {
                printf("[!] Unknown flag\n");
            }
        } else {
            fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
            err = ring_buffer__poll(rb, 100);
            if (err < 0 && err != -1) {
                fprintf(stderr, "Error polling ring buffer: %d\n", err);
                goto cleanup;
            }

            if (read(STDIN_FILENO, &n, 1) > 0)
                if (n == 'x' || n == 'X'){
                    log_flag = 0;
                    fcntl(STDIN_FILENO, F_SETFL, flags);
                }
                    
         }
    }
cleanup:
    // Detach the XDP program before exiting
    if (ifindex > 0) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    }

    // Clean up
    ring_buffer__free(rb);
    capture_ip_packet_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
