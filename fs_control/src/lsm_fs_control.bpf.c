#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "lsm_fs_control.h"

// Define required constants
#ifndef EPERM
#define EPERM 1
#endif

#ifndef MAY_WRITE
#define MAY_WRITE 0x02
#endif

char LICENSE[] SEC("license") = "GPL";

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct cache_key);
    __type(value, struct cache_value);
} cached_decisions SEC(".maps");

static inline int check_cache_decision(__u64 key) {
    struct cache_key cache_key = { .key = key };
    struct cache_value *value;
    
    value = bpf_map_lookup_elem(&cached_decisions, &cache_key);
    if (value) {
        // Return the cached decision: 0 for allowed, -EPERM for denied
        return value->allowed ? 0 : -EPERM;
    }
    return -1;  // Not in cache
}

static int handle_file_access(struct file *file, int operation) {
    if (!file)
        return -EPERM;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 inode = BPF_CORE_READ(file, f_inode, i_ino);
    __u64 device = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    
    // Generate cache key
    __u64 key = make_cache_key(pid, inode, device, operation);

    // Check cache first
    int cache_result = check_cache_decision(key);
    if (cache_result != -1) {  // If we have a cache entry
        return cache_result;    // Return the cached decision
    }

    // Create and submit new request
    struct access_request req = {
        .pid = pid,
        .inode = inode,
        .device = device,
        .operation = operation,
        .timestamp = bpf_ktime_get_ns()
    };
    
    bpf_probe_read_str(req.filename, sizeof(req.filename),
                      BPF_CORE_READ(file, f_path.dentry, d_name.name));

    bpf_map_update_elem(&pending_requests, &key, &req, BPF_ANY);

    // Wait for response
    #pragma unroll
    for (int i = 0; i < 1000; i++) {
        struct access_response *resp = bpf_map_lookup_elem(&request_responses, &key);
        if (resp) {
            bool allowed = resp->allowed;
            bpf_map_delete_elem(&request_responses, &key);
            bpf_map_delete_elem(&pending_requests, &key);
            return allowed ? 0 : -EPERM;
        }
        bpf_ktime_get_ns();
    }

    return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file, int ret) {
    if (ret != 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *monitored = bpf_map_lookup_elem(&target_pid, &pid);
    if (!monitored)
        return 0;

    return handle_file_access(file, OP_OPEN);
}

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask, int ret) {
    if (ret != 0)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *monitored = bpf_map_lookup_elem(&target_pid, &pid);
    if (!monitored)
        return 0;

    return handle_file_access(file, (mask & MAY_WRITE) ? OP_WRITE : OP_READ);
}
