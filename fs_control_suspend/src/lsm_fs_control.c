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
#include <sys/syscall.h>

static volatile bool exiting = false;
static bool debug_mode = false;  // Set to true to enable debug output
static struct lsm_fs_control_bpf *skel = NULL;
static struct process_state proc_state = {
    .pidfd = -1,
    .is_stopped = false,
    .target_pid = -1
};

static const char *op_strings[] = {
    [1] = "open",
    [2] = "read",
    [3] = "write"
};

// Forward declarations of all functions
static void sig_handler(int sig);
static char* get_proc_name(pid_t pid);
static void print_request(const struct access_request *req);
static bool ask_cache_decision(void);
static bool process_user_input(void);
static void check_existing_cache(const struct access_request *req, int cache_fd);
static int handle_requests(void);

// Signal handler implementation
static void sig_handler(int sig) {
    exiting = true;
}

// Get process name implementation
static char* get_proc_name(pid_t pid) {
    static char name[256];
    char path[256];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (!f) return NULL;
    
    if (fgets(name, sizeof(name), f)) {
        name[strcspn(name, "\n")] = 0;
        fclose(f);
        return name;
    }
    fclose(f);
    return NULL;
}

// Print request implementation
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

// Cache decision prompt implementation
static bool ask_cache_decision(void) {
    char input[10];
    printf("Would you like to remember this decision? [y/n]: ");
    fflush(stdout);
    if (!fgets(input, sizeof(input), stdin))
        return false;
    return (input[0] == 'y' || input[0] == 'Y');
}

// Process user input implementation
static bool process_user_input(void) {
    char input[10];
    if (!fgets(input, sizeof(input), stdin))
        return false;
    return (input[0] == 'y' || input[0] == 'Y');
}

// Check existing cache implementation
static void check_existing_cache(const struct access_request *req, int cache_fd) {
    struct cache_key key = {
        .key = make_cache_key(req->pid, req->inode, req->device, req->operation)
    };
    
    struct cache_value value;
    int err = bpf_map_lookup_elem(cache_fd, &key, &value);
    
    if (debug_mode) {
        printf("[DEBUG] Checking cache for PID=%d, Inode=%llu, Device=%llu, Op=%d, Key=%llx: %s\n",
               req->pid, (unsigned long long)req->inode, 
               (unsigned long long)req->device, req->operation,
               (unsigned long long)key.key,
               err == 0 ? "FOUND" : "NOT FOUND");
    }
}

static void stop_process(void) {
    if (!proc_state.is_stopped && proc_state.pidfd >= 0) {
        if (syscall(SYS_pidfd_send_signal, proc_state.pidfd, SIGSTOP, NULL, 0) == 0) {
            proc_state.is_stopped = true;
            if (debug_mode) {
                printf("[DEBUG] Process stopped\n");
            }
        } else {
            fprintf(stderr, "Failed to stop process: %s\n", strerror(errno));
        }
    }
}

static void continue_process(void) {
    if (proc_state.is_stopped && proc_state.pidfd >= 0) {
        if (syscall(SYS_pidfd_send_signal, proc_state.pidfd, SIGCONT, NULL, 0) == 0) {
            proc_state.is_stopped = false;
            if (debug_mode) {
                printf("[DEBUG] Process continued\n");
            }
        } else {
            fprintf(stderr, "Failed to continue process: %s\n", strerror(errno));
        }
    }
}

static int handle_requests(void) {
    struct access_request req;
    struct access_response resp = {0};
    struct cache_key cache_key = {0};
    struct cache_value cache_val = {0};
    __u64 lookup_key = 0;
    int err;

    int pending_fd = bpf_map__fd(skel->maps.pending_requests);
    int response_fd = bpf_map__fd(skel->maps.request_responses);
    int cache_fd = bpf_map__fd(skel->maps.cached_decisions);

    while (!exiting) {
        err = bpf_map_get_next_key(pending_fd, &lookup_key, &lookup_key);
        if (err) {
            usleep(100000);
            continue;
        }

        err = bpf_map_lookup_elem(pending_fd, &lookup_key, &req);
        if (err) {
            lookup_key = 0;
            continue;
        }

        // Stop the process while we wait for user input
        stop_process();

        cache_key.key = make_cache_key(req.pid, req.inode, req.device, req.operation);

        if (debug_mode) {
            check_existing_cache(&req, cache_fd);
        }

        // Look up in cache
        if (bpf_map_lookup_elem(cache_fd, &cache_key, &cache_val) == 0) {
            resp.allowed = cache_val.allowed;
            resp.timestamp = time(NULL);

            err = bpf_map_update_elem(response_fd, &lookup_key, &resp, BPF_ANY);
            if (err) {
                fprintf(stderr, "Error sending cached response: %s\n", strerror(errno));
            }

            bpf_map_delete_elem(pending_fd, &lookup_key);

            if (debug_mode) {
                printf("[DEBUG] Using cached decision: %s\n",
                       resp.allowed ? "ALLOW" : "DENY");
            }

            // Continue the process after using cached decision
            continue_process();

            lookup_key = 0;
            continue;
        }

        // Ask user for new decision
        print_request(&req);
        resp.allowed = process_user_input();
        resp.timestamp = time(NULL);

        if (resp.allowed) {
            bool cache_decision = ask_cache_decision();
            if (cache_decision) {
                cache_val.allowed = 1;
                cache_val.timestamp = time(NULL);

                err = bpf_map_update_elem(cache_fd, &cache_key, &cache_val, BPF_ANY);
                if (err) {
                    fprintf(stderr, "Error caching decision: %s\n", strerror(errno));
                }
            }
        }

        err = bpf_map_update_elem(response_fd, &lookup_key, &resp, BPF_ANY);
        if (err) {
            fprintf(stderr, "Error sending response: %s\n", strerror(errno));
        }

        // Continue the process after getting user decision
        continue_process();

        lookup_key = 0;
    }

    return 0;
}

int main(int argc, char **argv) {
    int err;
    __u8 val = 1;

    /* Parse command line arguments */
    if (argc != 3 || (strcmp(argv[1], "--pid") && strcmp(argv[1], "--name"))) {
        fprintf(stderr, "Usage: %s [--pid PID | --name PROCESS_NAME]\n", argv[0]);
        return 1;
    }

    /* Get target PID either directly or by process name */
    if (strcmp(argv[1], "--pid") == 0) {
        proc_state.target_pid = atoi(argv[2]);
    } else {
        char cmd[256];
        char buf[256];
        FILE *f;

        snprintf(cmd, sizeof(cmd), "pgrep -x '%s'", argv[2]);
        f = popen(cmd, "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f))
                proc_state.target_pid = atoi(buf);
            pclose(f);
        }
    }

    /* Verify target process exists */
    if (proc_state.target_pid == -1 || kill(proc_state.target_pid, 0) == -1) {
        fprintf(stderr, "Invalid process specified\n");
        return 1;
    }

    /* Open pidfd for the target process */
    proc_state.pidfd = syscall(SYS_pidfd_open, proc_state.target_pid, 0);
    if (proc_state.pidfd < 0) {
        fprintf(stderr, "Failed to open pidfd: %s\n", strerror(errno));
        return 1;
    }

    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(NULL);

    /* Open BPF application */
    skel = lsm_fs_control_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = -1;
        goto cleanup;
    }

    /* Load & verify BPF programs */
    err = lsm_fs_control_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF programs\n");
        goto cleanup;
    }

    /* Attach BPF programs */
    err = lsm_fs_control_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    /* Update map with target PID */
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.target_pid),
        &proc_state.target_pid,
        &val,
        BPF_ANY
    );
    if (err) {
        fprintf(stderr, "Failed to update target PID map: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Print startup message */
    char *proc_name = get_proc_name(proc_state.target_pid);
    printf("Started monitoring process %d (%s)\n",
           proc_state.target_pid,
           proc_name ? proc_name : "unknown");
    printf("Press Ctrl+C to exit\n");

    /* Main event loop */
    err = handle_requests();

cleanup:
    /* Cleanup phase */
    if (proc_state.pidfd >= 0) {
        /* Ensure process is running before we exit */
        if (proc_state.is_stopped) {
            if (syscall(SYS_pidfd_send_signal, proc_state.pidfd, SIGCONT, NULL, 0) == 0) {
                printf("Resumed process before exit\n");
            }
        }
        close(proc_state.pidfd);
    }

    /* Cleanup BPF resources */
    if (skel) {
        lsm_fs_control_bpf__destroy(skel);
    }

    return err != 0;
}
