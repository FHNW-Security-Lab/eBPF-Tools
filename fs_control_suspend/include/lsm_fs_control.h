/* include/lsm_fs_control.h */
#ifndef __LSM_FS_CONTROL_H
#define __LSM_FS_CONTROL_H

struct access_request {
    __u32 pid;
    __u64 inode;
    __u64 device;
    __u32 operation;
    __u64 timestamp;
    char filename[256];
};

struct access_response {
    __u32 allowed;
    __u64 timestamp;
};

struct process_state {
    int pidfd;         // pidfd for the target process
    bool is_stopped;   // track if process is currently stopped
    pid_t target_pid;  // store the target PID
};

// Changed to use single __u64 key for better matching
struct cache_key {
    __u64 key;  // Combination of pid + inode + device + operation
};

struct cache_value {
    __u32 allowed;
    __u64 timestamp;
};

#define OP_OPEN  1
#define OP_READ  2
#define OP_WRITE 3

static inline __u64 make_cache_key(__u32 pid, __u64 inode, __u64 device, __u32 operation) {
    return ((__u64)pid << 32) | (inode ^ device ^ operation);
}
#endif
