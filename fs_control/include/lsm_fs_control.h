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

#define OP_OPEN  1
#define OP_READ  2
#define OP_WRITE 3

#endif /* __LSM_FS_CONTROL_H */

