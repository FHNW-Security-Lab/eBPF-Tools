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
