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

static volatile bool exiting = false;
static struct lsm_fs_control_bpf *skel = NULL;
static bool debug_mode = true;

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

        cache_key.key = make_cache_key(req.pid, req.inode, req.device, req.operation);
        
        if (debug_mode) {
            check_existing_cache(&req, cache_fd);
        }

        // Look up in cache
        if (bpf_map_lookup_elem(cache_fd, &cache_key, &cache_val) == 0) {
            // Use cached decision
            resp.allowed = cache_val.allowed;
            resp.timestamp = time(NULL);
            
            // Send response immediately for cached decisions
            err = bpf_map_update_elem(response_fd, &lookup_key, &resp, BPF_ANY);
            if (err) {
                fprintf(stderr, "Error sending cached response: %s\n", strerror(errno));
            }
            
            // Clean up the pending request
            bpf_map_delete_elem(pending_fd, &lookup_key);
            
            if (debug_mode) {
                printf("[DEBUG] Using cached decision: %s\n", 
                       resp.allowed ? "ALLOW" : "DENY");
            }
            
            lookup_key = 0;
            continue;
        } else {
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
                    } else if (debug_mode) {
                        printf("[DEBUG] Successfully cached decision for Key=%llx (PID=%d, Inode=%llu, Device=%llu, Op=%d)\n",
                               (unsigned long long)cache_key.key,
                               req.pid, (unsigned long long)req.inode,
                               (unsigned long long)req.device, req.operation);
                    }
                }
            }
        }

        err = bpf_map_update_elem(response_fd, &lookup_key, &resp, BPF_ANY);
        if (err) {
            fprintf(stderr, "Error sending response: %s\n", strerror(errno));
        }

        lookup_key = 0;
    }

    return 0;
}

int main(int argc, char **argv) {
    int err;
    pid_t target_pid = -1;
    __u8 val = 1;

    if (argc != 3 || (strcmp(argv[1], "--pid") && strcmp(argv[1], "--name"))) {
        fprintf(stderr, "Usage: %s [--pid PID | --name PROCESS_NAME]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--pid") == 0) {
        target_pid = atoi(argv[2]);
    } else {
        char cmd[256];
        char buf[256];
        FILE *f;
        
        snprintf(cmd, sizeof(cmd), "pgrep -x '%s'", argv[2]);
        f = popen(cmd, "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f))
                target_pid = atoi(buf);
            pclose(f);
        }
    }

    if (target_pid == -1 || kill(target_pid, 0) == -1) {
        fprintf(stderr, "Invalid process specified\n");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Set up libbpf errors and debug info callback
    libbpf_set_print(NULL);

    // Open BPF application
    skel = lsm_fs_control_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load & verify BPF programs
    err = lsm_fs_control_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF programs\n");
        goto cleanup;
    }

    // Attach BPF programs
    err = lsm_fs_control_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    // Set target PID in map
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.target_pid),
        &target_pid,
        &val,
        BPF_ANY
    );
    if (err) {
        fprintf(stderr, "Failed to update target PID\n");
        goto cleanup;
    }

    char *proc_name = get_proc_name(target_pid);
    printf("Started monitoring process %d (%s)\n", 
           target_pid, 
           proc_name ? proc_name : "unknown");
    printf("Press Ctrl+C to exit\n");

    err = handle_requests();

cleanup:
    lsm_fs_control_bpf__destroy(skel);
    return err != 0;
}
