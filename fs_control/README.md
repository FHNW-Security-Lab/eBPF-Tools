# File System Control (`fs_control.bpf.c`)

An eBPF Tool to monitor file access events of a specific process, providing insights into file operations like open, read, and write.

## Overview

`fs_control` is a command-line utility designed to manage file activities performed by a specified process. It leverages eBPF technology to gather real-time information about file access, which can be used for forensic analysis, troubleshooting, or general monitoring of process behavior.

## Features

- Control file access operations including **open**, **read**, and **write**.
- Filters events based on **PID** or **process name**.
- Option to show or hide file descriptor operations.
- Provides full file paths where possible, using `/proc` information.

## Warning

- The tool is under development and some processes crash. Also it does not cache access to operations yet, so it can be annoying.

## Required Settings

Requies eBPF to be enabled for LSM (`/etc/default/grup`, add `bpf` to `GRUB_CMDLINE_LINUX`, e.g. `GRUB_CMDLINE_LINUX="lsm=landlock,bpf"`)

- Settings that may be required:

```bash
sudo sysctl -w kernel.unprivileged_bpf_disabled=0
sudo sysctl -w kernel.perf_event_paranoid=1
sudo sysctl -w net.core.bpf_jit_enable=1
sudo setcap cap_bpf=eip ./dist/bin/lsm_fs_control
```
 
- To verify the setting:

 ```bash
$ grep LSM /boot/config-$(uname -r) | grep BPF
CONFIG_BPF_LSM=y

$ cat /sys/kernel/security/lockdown
[none] integrity confidentiality

$ cat /sys/kernel/security/lsm
lockdown,capability,landlock,bpf,ima,evm
```

## Usage

Build:

```bash
make deps
make
```

or to specify by process name:

```bash
sudo ./dist/bin/lsm_fs_control --name <process-name>
sudo ./dist/bin/lsm_fs_control --pid <process-pid>
```

### Arguments

- `--pid <PID>`: The PID of the process to monitor.
- `--name <process_name>`: The name of the process to control.

## Signals and Clean Exit

The tool gracefully handles `Ctrl+C` to stop monitoring and exit cleanly.

## License

This project is licensed under BSD 3-Clause Licence.
