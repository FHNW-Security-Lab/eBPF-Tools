#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lsm_fs_control.h"
#include "lsm_fs_control.skel.h"

// Global variables
static volatile bool exiting = false;
static struct lsm_fs_control_bpf *skel = NULL;

// File operation string mappings
static const char *op_strings[] = {
    [1] = "open",
    [2] = "read",
    [3] = "write"
};

// Signal handler
static void sig_handler(int sig) {
    exiting = true;
}

// Helper to get process name from pid
static char* get_proc_name(pid_t pid) {
    static char name[256];
    char path[256];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (!f)
        return NULL;
    
    if (fgets(name, sizeof(name), f)) {
        name[strcspn(name, "\n")] = 0;
        fclose(f);
        return name;
    }
    
    fclose(f);
    return NULL;
}

// Get PID from process name
static pid_t get_pid_by_name(const char *name) {
    char cmd[256];
    char buf[256];
    FILE *f;
    pid_t pid = -1;

    snprintf(cmd, sizeof(cmd), "pgrep -x '%s'", name);
    f = popen(cmd, "r");
    if (!f)
        return -1;

    if (fgets(buf, sizeof(buf), f))
        pid = atoi(buf);

    pclose(f);
    return pid;
}

// Print request details
static void print_request(const struct access_request *req) {
    char *proc_name = get_proc_name(req->pid);
    char timestr[64];
    time_t t = req->timestamp / 1000000000;
    strftime(timestr, sizeof(timestr), "%H:%M:%S", localtime(&t));

    printf("\n[%s] Process %s (PID %d) attempting to %s file:\n", 
           timestr, proc_name ? proc_name : "unknown", req->pid, 
           op_strings[req->operation]);
    printf("File: %s\n", req->filename);
    printf("Inode: %llu, Device: %llu\n", (unsigned long long)req->inode, 
           (unsigned long long)req->device);
    printf("Allow this operation? [y/n]: ");
    fflush(stdout);
}

// Process user input for a request
static bool process_user_input(void) {
    char input[10];
    if (!fgets(input, sizeof(input), stdin))
        return false;
    int res = (input[0] == 'y' || input[0] == 'Y');
    printf("User response was: %d", res);
    return res;
}

// Main loop to handle access requests
static int handle_requests(void) {
    struct access_request req;
    struct access_response resp = {0};
    __u64 lookup_key = 0;
    int err;
    int pending_fd = bpf_map__fd(skel->maps.pending_requests);
    int response_fd = bpf_map__fd(skel->maps.request_responses);

    while (!exiting) {
        // Find next request
        err = bpf_map_get_next_key(pending_fd, &lookup_key, &lookup_key);
        if (err) {
            usleep(100000); // Sleep 100ms if no requests
            continue;
        }

        // Get request details
        err = bpf_map_lookup_elem(pending_fd, &lookup_key, &req);
        if (err) {
            lookup_key = 0;
            continue;
        }

        // Print request and get user decision
        print_request(&req);
        resp.allowed = process_user_input();
        resp.timestamp = time(NULL);

        // Send response
        err = bpf_map_update_elem(response_fd,
                                 &lookup_key,
                                 &resp,
                                 BPF_ANY);
        
        if (err) {
            fprintf(stderr, "Error sending response: %s\n", strerror(errno));
        }

        lookup_key = 0;
    }

    return 0;
}

// Libbpf print callback
static int libbpf_print_fn(enum libbpf_print_level level, 
                          const char *format, 
                          va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    int err;
    pid_t target_pid = -1;
    __u8 val = 1;
    const char *target_name = NULL;

    // Parse command line arguments
    if (argc != 3) {
        fprintf(stderr, "Usage: %s [--pid PID | --name PROCESS_NAME]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--pid") == 0) {
        target_pid = atoi(argv[2]);
    } else if (strcmp(argv[1], "--name") == 0) {
        target_name = argv[2];
    } else {
        fprintf(stderr, "Usage: %s [--pid PID | --name PROCESS_NAME]\n", argv[0]);
        return 1;
    }

    // If process name is provided, get its PID
    if (target_pid == -1 && target_name) {
        target_pid = get_pid_by_name(target_name);
        if (target_pid == -1) {
            fprintf(stderr, "Could not find process: %s\n", target_name);
            return 1;
        }
    }

    // Verify process exists
    if (kill(target_pid, 0) == -1) {
        fprintf(stderr, "Process %d does not exist\n", target_pid);
        return 1;
    }

    // Set up signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Set up libbpf logging
    libbpf_set_print(libbpf_print_fn);

    // Open BPF skeleton
    skel = lsm_fs_control_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = lsm_fs_control_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Attach BPF programs
    err = lsm_fs_control_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Set target PID in map
    int target_fd = bpf_map__fd(skel->maps.target_pid);
    err = bpf_map_update_elem(target_fd,
                             &target_pid,
                             &val,
                             BPF_ANY);
    
    if (err) {
        fprintf(stderr, "Failed to update target PID: %d\n", err);
        goto cleanup;
    }

    printf("Started monitoring process %d (%s)\n", 
           target_pid, 
           get_proc_name(target_pid));
    printf("Press Ctrl+C to exit\n");

    // Main loop
    err = handle_requests();

cleanup:
    lsm_fs_control_bpf__destroy(skel);
    return err != 0;
}

