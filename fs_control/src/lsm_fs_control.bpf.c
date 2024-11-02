#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "lsm_fs_control.h"

// Define required constants
#define EPERM 1
#define MAY_WRITE 0x2

char LICENSE[] SEC("license") = "GPL";

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct access_request);
} pending_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, struct access_response);
} request_responses SEC(".maps");

// Helper function to generate a unique request ID
static __u64 gen_request_id(__u32 pid, __u64 inode, __u64 device, __u32 operation) {
    return ((__u64)pid << 32) | (inode ^ device ^ operation);
}

// Helper function to check if process should be monitored
static inline bool should_monitor_process(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *monitored = bpf_map_lookup_elem(&target_pid, &pid);
    return monitored != NULL;
}

// Helper function to wait for user response
static bool wait_for_response(__u64 request_id) {
    struct access_response *response;
    
    // Poll for response with timeout
    #pragma unroll
    for (int i = 0; i < 1000; i++) {
        response = bpf_map_lookup_elem(&request_responses, &request_id);
        if (response) {
            bool allowed = response->allowed;
            bpf_map_delete_elem(&request_responses, &request_id);
            bpf_map_delete_elem(&pending_requests, &request_id);
            return allowed;
        }
        bpf_ktime_get_ns(); // Small delay
    }
    
    return false; // Timeout - deny by default
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file, int ret) {
    if (!should_monitor_process() || ret != 0)
        return 0;

    struct access_request req = {};
    
    // Get file information using BPF_CORE_READ for safe access
    req.inode = BPF_CORE_READ(file, f_inode, i_ino);
    req.device = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    req.pid = bpf_get_current_pid_tgid() >> 32;
    req.operation = 1; // open
    req.timestamp = bpf_ktime_get_ns();
    
    // Get filename (best effort)
    bpf_probe_read_str(req.filename, sizeof(req.filename), 
                      BPF_CORE_READ(file, f_path.dentry, d_name.name));

    __u64 request_id = gen_request_id(req.pid, req.inode, req.device, req.operation);
    
    // Store request and wait for response
    bpf_map_update_elem(&pending_requests, &request_id, &req, BPF_ANY);
    
    return wait_for_response(request_id) ? 0 : -EPERM;
}

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask, int ret) {
    if (!should_monitor_process() || ret != 0)
        return 0;

    struct access_request req = {};
    
    // Get file information using BPF_CORE_READ for safe access
    req.inode = BPF_CORE_READ(file, f_inode, i_ino);
    req.device = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    req.pid = bpf_get_current_pid_tgid() >> 32;
    req.operation = (mask & MAY_WRITE) ? 3 : 2; // write : read
    req.timestamp = bpf_ktime_get_ns();
    
    // Get filename (best effort)
    bpf_probe_read_str(req.filename, sizeof(req.filename), 
                      BPF_CORE_READ(file, f_path.dentry, d_name.name));

    __u64 request_id = gen_request_id(req.pid, req.inode, req.device, req.operation);
    
    // Store request and wait for response
    bpf_map_update_elem(&pending_requests, &request_id, &req, BPF_ANY);
    
    return wait_for_response(request_id) ? 0 : -EPERM;
}

