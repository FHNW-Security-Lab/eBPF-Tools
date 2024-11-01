// fs_monitor.bpf.c
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

#define DNAME_INLINE_LEN 32

// Event structure
struct event_t {
    char comm[16];
    u32 pid;
    char fname[256];
    int op;
    int is_fd;
};

// Map to store target PID
BPF_HASH(target_pid, u32, u8, 1);
BPF_PERF_OUTPUT(events);

static inline int get_path_str(struct path *path, char *buf, size_t size)
{
    if (!path)
        return -1;

    struct dentry *dentry = path->dentry;
    struct vfsmount *vfsmnt = path->mnt;
    
    if (!dentry)
        return -1;

    // Get the mount point path
    if (vfsmnt) {
        const char *mount_point = vfsmnt->mnt_root->d_name.name;
        if (mount_point) {
            bpf_probe_read_str(buf, size, mount_point);
        }
    }

    // Get the file name
    const unsigned char *name = dentry->d_name.name;
    if (name) {
        bpf_probe_read_str(buf, size, name);
    }

    return 0;
}

static inline int handle_file_access(struct pt_regs *ctx, struct file *file, int op)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check if this is the PID we want to monitor
    u8 *should_track = target_pid.lookup(&pid);
    if (!should_track) {
        return 0;
    }

    struct event_t event = {};
    
    // Get process name and PID
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.pid = pid;
    event.op = op;
    
    // Get file path
    if (file) {
        get_path_str(&file->f_path, event.fname, sizeof(event.fname));
        
        // Check if it's a file descriptor
        const char *name = file->f_path.dentry->d_name.name;
        char first_char;
        bpf_probe_read(&first_char, 1, name);
        event.is_fd = first_char >= '0' && first_char <= '9';
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe__vfs_open(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    return handle_file_access(ctx, file, 1);
}

int kprobe__vfs_read(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    return handle_file_access(ctx, file, 2);
}

int kprobe__vfs_write(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    return handle_file_access(ctx, file, 3);
}

