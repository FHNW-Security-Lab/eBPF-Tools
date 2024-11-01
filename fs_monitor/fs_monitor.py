#!/usr/bin/env python

from bcc import BPF
import ctypes as ct
import argparse
import signal
import os
from collections import OrderedDict

# Operation mapping
OP_MAP = {
    1: 'opens',
    2: 'reads',
    3: 'writes'
}

class FileAccess:
    def __init__(self, comm, pid, ops):
        self.comm = comm
        self.pid = pid
        self.ops = ops  # Set of operations

    def add_op(self, op):
        self.ops.add(op)

    def __str__(self):
        ops_list = sorted(list(self.ops))
        ops_str = ', '.join(ops_list)
        return f"{self.comm} (PID: {self.pid}) {ops_str}"

def get_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except:
        return None

def get_full_path(pid, fname):
    """Try to resolve the full path using /proc/pid/fd/ if available"""
    try:
        proc_path = f"/proc/{pid}/cwd"
        if os.path.islink(proc_path):
            cwd = os.readlink(proc_path)
            full_path = os.path.normpath(os.path.join(cwd, fname))
            return full_path
    except:
        pass
    return fname

def parse_args():
    parser = argparse.ArgumentParser(description='Monitor file access of a specific process')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--pid', type=int, help='PID of the process to monitor')
    group.add_argument('--name', type=str, help='Name of the process to monitor')
    parser.add_argument('--show-fd', action='store_true', 
                      help='Show file descriptor operations (default: false)')
    return parser.parse_args()

args = parse_args()

# If process name is provided, get its PID
if args.name:
    import subprocess
    try:
        pid = int(subprocess.check_output(['pgrep', '-f', args.name]).split()[0])
    except:
        print(f"No process found with name: {args.name}")
        exit(1)
else:
    pid = args.pid

# Verify PID exists
if not os.path.exists(f"/proc/{pid}"):
    print(f"Process with PID {pid} not found")
    exit(1)

process_name = get_process_name(pid)
if not process_name:
    print(f"Could not get process name for PID {pid}")
    exit(1)

print(f"Starting monitoring of {process_name} (PID: {pid})")
if not args.show_fd:
    print("File descriptor operations are hidden. Use --show-fd to see them.")

# Load BPF program
with open('fs_monitor.bpf.c', 'r') as f:
    bpf_text = f.read()

# Initialize BPF
try:
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Failed to compile BPF program: {e}")
    exit(1)

# Set the PID to monitor
b["target_pid"][ct.c_uint32(pid)] = ct.c_uint8(1)

# Keep track of unique files and their operations
file_accesses = OrderedDict()

def print_event(cpu, data, size):
    event = b["events"].event(data)
    fname = event.fname.decode('utf-8', 'replace')
    
    # Skip empty filenames and . or ..
    if not fname or fname in [".", ".."]:
        return
        
    # Skip file descriptor operations unless explicitly requested
    if event.is_fd and not args.show_fd:
        return

    # Try to get full path
    full_path = get_full_path(event.pid, fname)

    # Get operation name
    op = OP_MAP.get(event.op, 'accesses')
    comm = event.comm.decode('utf-8', 'replace')
    
    if full_path not in file_accesses:
        file_accesses[full_path] = FileAccess(comm, event.pid, {op})
        # Print immediately when we see a new file
        print(f"{file_accesses[full_path]} {full_path}")
    else:
        # Update operations for existing file
        old_ops = file_accesses[full_path].ops.copy()
        file_accesses[full_path].add_op(op)
        # Print only if we see a new operation type
        if old_ops != file_accesses[full_path].ops:
            print(f"{file_accesses[full_path]} {full_path}")

# Attach event handler
b["events"].open_perf_buffer(print_event)

# Clean exit on Ctrl+C
def signal_handler(signum, frame):
    print("\nMonitoring stopped")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main loop
print("Monitoring file access... Press Ctrl+C to stop")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
