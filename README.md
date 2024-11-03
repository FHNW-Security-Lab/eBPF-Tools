# eBPF-Tools

A collection of tools based on eBPF (Extended Berkeley Packet Filter) for forensics, security control, and various other applications.

## Overview

eBPF is a powerful technology that allows programs to run inside the Linux kernel safely and efficiently, making it a useful mechanism for a wide range of security, monitoring, and forensic tasks. This repository provides tools that leverage eBPF to aid in:

- **Forensics**: Gathering detailed runtime information from the system to support incident response and analysis.
- **Security Control**: Enforcing security policies, monitoring system activity, and detecting anomalies.
- **Monitoring and Observability**: Providing in-depth visibility into system behavior and network activity.

## Repository

The project is hosted on GitHub: [eBPF Forensics Tools](https://github.com/FHNW-Security-Lab/eBPF-Tools)

Clone the repository using:

```bash
git clone https://github.com/FHNW-Security-Lab/eBPF-Tools```
```
## Tools Included

### 1. **eBPF Forensics Monitor**

A eBPF to control the file system access for a specific tool. Helpful to enforce file system rules on processes.

### 2. **eBPF Process control**

A eBPF to monitor the file system access for a specific tool. Helpful for forensics and to find data left on the disk by programs 

## Requirements

- Linux kernel version 4.18 or newer (eBPF support required).
- `bcc` or `libbpf` library installed for eBPF interaction.
- Requies eBPF to be enabled for LSM (/etc/default/grup, add bpf to GRUB_CMDLINE_LINUX, e.g. GRUB_CMDLINE_LINUX="lsm=landlock,bpf")
 

Install the required dependencies using:

```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

## License

This project is licensed under BSD 3-Clause Licence.

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request.

## Contact

For any questions or issues, please contact us.


