# File System Monitor (`fs_monitor.py`)

An eBPF Tool to monitor file access events of a specific process, providing insights into file operations like open, read, and write.

## Overview

`fs_monitor.py` is a command-line utility designed to observe file activities performed by a specified process. It leverages eBPF technology to gather real-time information about file access, which can be used for forensic analysis, troubleshooting, or general monitoring of process behavior.

This tool is particularly useful for:

- **Forensic Investigations**: Tracking file operations of potentially suspicious processes.
- **System Monitoring**: Understanding what files a specific application is accessing during its execution.
- **Debugging and Analysis**: Identifying unexpected file accesses or resource usage by a process.

## Features

- Monitors file access operations including **open**, **read**, and **write**.
- Filters events based on **PID** or **process name**.
- Option to show or hide file descriptor operations.
- Provides full file paths where possible, using `/proc` information.

## Prerequisites

- **Linux Kernel** version 4.18 or newer (supports eBPF).
- **Python 3.6** or newer.
- **bcc** library installed.

Install `bcc` and necessary headers:

```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

## Usage

Run the tool using the following command:

```bash
sudo python3 fs_monitor.py --pid <PID> [--show-fd]
```

or to specify by process name:

```bash
sudo python3 fs_monitor.py --name <process_name> [--show-fd]
```

### Arguments

- `--pid <PID>`: The PID of the process to monitor.
- `--name <process_name>`: The name of the process to monitor.
- `--show-fd`: Optionally show file descriptor operations.

## Example Output

When monitoring a process, the output will display information about file access operations:

```
Starting monitoring of python (PID: 1234)
File descriptor operations are hidden. Use --show-fd to see them.
Monitoring file access... Press Ctrl+C to stop
python (PID: 1234) opens /home/user/data.txt
python (PID: 1234) reads /home/user/data.txt
python (PID: 1234) writes /home/user/output.log
```

The output provides details on the command (`comm`), process ID (`PID`), operation type (`open`, `read`, `write`), and the file path being accessed.

## Signals and Clean Exit

The tool gracefully handles `Ctrl+C` to stop monitoring and exit cleanly:

```bash
Monitoring stopped
```

## License

This project is licensed under BSD 3-Clause Licence.



