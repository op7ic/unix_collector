# unix_collector

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/Version-2.0-green.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Multi--UNIX-orange.svg)]()

A comprehensive live forensic collection script for UNIX-like systems, designed to gather critical system information for forensic investigations and incident response.

As a single shell script, ```unix_collector``` is easy to upload and execute, without the need for untarring, compiling, installation, or an internet connection to download additional components. The script can be run either as a normal user or as root, though it performs more effectively when executed as root, as this allows it to access a wider range of system files and artifacts. 

[![Imgur](https://i.imgur.com/6xMcGIg.gif)](#)

## 🖥️ Supported Platforms

UNIX Collector supports a wide range of UNIX-like operating systems with automatic platform detection:

### Operating Systems
- [![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
- [![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)](https://www.apple.com/macos/)
- [![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://www.android.com/)
- [![FreeBSD](https://img.shields.io/badge/FreeBSD-AB2B28?style=for-the-badge&logo=freebsd&logoColor=white)](https://www.freebsd.org/)
- [![OpenBSD](https://img.shields.io/badge/OpenBSD-F2CA30?style=for-the-badge&logo=openbsd&logoColor=black)](https://www.openbsd.org/)
- [![NetBSD](https://img.shields.io/badge/NetBSD-FF6600?style=for-the-badge&logo=netbsd&logoColor=white)](https://www.netbsd.org/)
- [![Solaris](https://img.shields.io/badge/Solaris-FF6C2C?style=for-the-badge&logo=oracle&logoColor=white)](https://www.oracle.com/solaris/)
- [![AIX](https://img.shields.io/badge/AIX-052FAD?style=for-the-badge&logo=ibm&logoColor=white)](https://www.ibm.com/power/operating-systems/aix)
- [![HP--UX](https://img.shields.io/badge/HP--UX-0096D6?style=for-the-badge&logo=hp&logoColor=white)](https://www.hpe.com/)

### Container & Virtualization Platforms
- [![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
- [![Kubernetes](https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](https://kubernetes.io/)
- [![Podman](https://img.shields.io/badge/Podman-892CA0?style=for-the-badge&logo=podman&logoColor=white)](https://podman.io/)
- [![Containerd](https://img.shields.io/badge/Containerd-575757?style=for-the-badge&logo=containerd&logoColor=white)](https://containerd.io/)
- [![LXC/LXD](https://img.shields.io/badge/LXC/LXD-E95420?style=for-the-badge&logo=linuxcontainers&logoColor=white)](https://linuxcontainers.org/)
- [![VMware ESXi](https://img.shields.io/badge/VMware_ESXi-607078?style=for-the-badge&logo=vmware&logoColor=white)](https://www.vmware.com/products/esxi-and-esx.html)
- [![VirtualBox](https://img.shields.io/badge/VirtualBox-183A61?style=for-the-badge&logo=virtualbox&logoColor=white)](https://www.virtualbox.org/)
- [![KVM/libvirt](https://img.shields.io/badge/KVM/libvirt-FF6600?style=for-the-badge&logo=kvm&logoColor=white)](https://www.linux-kvm.org/)
- [![Proxmox](https://img.shields.io/badge/Proxmox-E57000?style=for-the-badge&logo=proxmox&logoColor=white)](https://www.proxmox.com/)

### Specialized Platforms
- [![NetScaler](https://img.shields.io/badge/NetScaler-1B75BB?style=for-the-badge&logo=citrix&logoColor=white)](https://www.citrix.com/)
- [![IoT/Embedded](https://img.shields.io/badge/IoT%2FEmbedded-6DB33F?style=for-the-badge&logo=linux&logoColor=white)]()

### Linux Distributions
- [![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat-square&logo=ubuntu&logoColor=white)](https://ubuntu.com/)
- [![Debian](https://img.shields.io/badge/Debian-A81D33?style=flat-square&logo=debian&logoColor=white)](https://www.debian.org/)
- [![Red Hat](https://img.shields.io/badge/Red%20Hat-EE0000?style=flat-square&logo=redhat&logoColor=white)](https://www.redhat.com/)
- [![CentOS](https://img.shields.io/badge/CentOS-262577?style=flat-square&logo=centos&logoColor=white)](https://www.centos.org/)
- [![SUSE](https://img.shields.io/badge/SUSE-0C322C?style=flat-square&logo=suse&logoColor=white)](https://www.suse.com/)
- [![Arch](https://img.shields.io/badge/Arch-1793D1?style=flat-square&logo=arch-linux&logoColor=white)](https://archlinux.org/)
- [![Gentoo](https://img.shields.io/badge/Gentoo-54487A?style=flat-square&logo=gentoo&logoColor=white)](https://www.gentoo.org/)
- [![Slackware](https://img.shields.io/badge/Slackware-000000?style=flat-square&logo=slackware&logoColor=white)](http://www.slackware.com/)

**Note**: The script automatically detects the platform and adjusts collection methods accordingly. For systems not explicitly listed, use the `--platform=generic` option for best-effort collection.

# Features

### 🔍 What It Collects

The script gathers **250+ distinct forensic artifacts** to help identify potential system compromises:

| Category | Artifact Count | Key Artifacts |
|----------|-------|---------------|
| **System Information** | ~30 | Kernel version, hardware inventory, BIOS/UEFI, timezone, installation date |
| **Storage & Filesystems** | ~40 | Disk partitions, RAID arrays, LVM volumes, ZFS datasets, mount points |
| **Process Analysis** | ~25 | Running processes, command lines, file handles, deleted binaries, memory maps |
| **Persistence Mechanisms** | ~35 | Cron jobs, at tasks, systemd timers, rc scripts, kernel modules |
| **Network Configuration** | ~20 | Interfaces, routing tables, connections, firewall rules, ARP cache |
| **User & Authentication** | ~15 | User accounts, groups, SSH configs, sudo rules, Kerberos tickets |
| **System Logs** | ~10 | /var/log, audit logs, boot logs, security events, dmesg |
| **Virtual Systems** | ~45 | VMware ESXi (25), VirtualBox (10), KVM/libvirt (7), others (3) |
| **Container Platforms** | ~45 | Docker (13), Podman (11), LXC (12), Containerd (2), Proxmox (3) |
| **File Hashes** | 3 | MD5, SHA1, SHA256 for all collected binaries |
| **Configuration Files** | ~20 | /etc configs, systemd units, network settings |
| **Additional Data** | ~15 | Home directories, temp files, installed packages, compiler tools |

**System & Hardware**
- Complete hardware inventory and system information
- Kernel version, modules, and taint status
- BIOS/UEFI settings and boot configuration
- Storage devices, partitions, and RAID configurations

**Files & Processes**
- Full filesystem timeline with inode and MAC times
- Running processes with command lines and file descriptors
- Process memory maps and deleted binaries detection
- SUID/SGID binaries with cryptographic hashes
- Open files and network connections per process

**Users & Authentication**
- User accounts, groups, and password policies
- SSH keys and configurations
- Sudo rules and PAM settings
- Login history and active sessions
- Kerberos tickets and authentication tokens

**Persistence Mechanisms**
- Cron jobs, at tasks, and systemd timers
- Init scripts and startup items
- Kernel modules and drivers
- System services and daemons

**Network & Communications**
- Network interfaces and routing tables
- Active connections and listening ports
- Firewall rules and packet filters
- DNS configuration and host mappings
- ARP cache and neighbor tables

**Logs & Audit Trails**
- System logs (/var/log, /var/adm)
- Authentication logs and security events
- Audit daemon logs and rules
- Boot and kernel messages
- Application-specific logs

**Container & Virtualization**
- Docker/Podman containers, images, and volumes
- Virtual machine inventories and configurations
- Container runtime configs and logs
- Hypervisor settings and resource allocations

**Additional Artifacts**
- Installed software and patch levels
- Configuration files from /etc
- Temporary files and caches
- User home directories
- Browser artifacts and history
- Scheduled tasks and services

## 🚀 Quick Start

### Installation

```bash
# Download the script (single file, no dependencies)
wget https://raw.githubusercontent.com/op7ic/unix_collector/main/unix_collector.sh

# Make it executable
chmod +x unix_collector.sh
```

### Basic Usage

```bash
# Run with auto-detection (recommended: run as root for full collection)
sudo ./unix_collector.sh

# Run as normal user (limited collection)
./unix_collector.sh

# Specify platform manually
sudo ./unix_collector.sh --platform=Linux
```

**💡 Tip**: While the script can run as a normal user, running as root provides access to more comprehensive forensic artifacts including system logs, process memory maps, and privileged configuration files.

### Available Platform Options
- `solaris` - Sun/Oracle Solaris
- `aix` - IBM AIX
- `mac` - macOS/Darwin
- `linux` - Generic Linux
- `hpux` - HP-UX
- `android` - Android devices
- `generic` - Unknown UNIX systems

### Example deployment and collection

```bash
# 1. Transfer script to target system
scp unix_collector.sh user@target:/tmp/

# 2. SSH to target
ssh user@target

# 3. Run collector
cd /tmp && sudo ./unix_collector.sh --quiet

# 4. Transfer results back
scp collector-*.tar.xz analyst@forensics:/cases/

# 5. Extract and analyze
tar -xf collector-*.tar.xz
```

## 📋 Key Features

[![Self-Contained](https://img.shields.io/badge/Self--Contained-brightgreen?style=flat-square)](https://github.com/op7ic/unix_collector)
[![Zero--Dependencies](https://img.shields.io/badge/Zero--Dependencies-blue?style=flat-square)](https://github.com/op7ic/unix_collector)
[![Read--Only](https://img.shields.io/badge/Read--Only-orange?style=flat-square)](https://github.com/op7ic/unix_collector)
[![Multi--Hash](https://img.shields.io/badge/Multi--Hash-purple?style=flat-square)](https://github.com/op7ic/unix_collector)
[![Auto--Compress](https://img.shields.io/badge/Auto--Compress-red?style=flat-square)](https://github.com/op7ic/unix_collector)

- **🔧 Self-Contained**: Single shell script with no external dependencies
- **🌐 Air-Gap Ready**: No internet connection required for operation
- **🛡️ Non-Invasive**: Read-only operations preserve evidence integrity
- **🔍 Comprehensive**: Collects 250+ types of forensic artifacts
- **⚡ Efficient**: Configurable file size limits prevent resource exhaustion
- **🔐 Hash Verification**: Multiple algorithms (MD5, SHA1, SHA256) for evidence validation
- **📊 Timeline Analysis**: Complete filesystem timeline with inode and timestamp data exported both to body and csv files

## 💾 Output Format

### Archive Structure
The script creates a timestamped archive: `collector-hostname-DD-MM-YYYY.tar[.xz|.bz2|.gz]`

Compression is automatically selected based on available tools:
1. **XZ** (smallest size, if available)
2. **BZIP2** (good compression)
3. **GZIP** (fastest)
4. **TAR** (no compression, fallback in case other tools don't exist)

### Directory Organization
```
collector-hostname-DD-MM-YYYY/
├── general/           # System information, kernel, hardware
├── software/          # Installed packages and patches
├── logs/             # System and application logs
├── homedir/          # User home directories
├── procfiles/        # Process information from /proc
├── tmpfiles/         # Temporary file preservation
├── setuid/           # SUID/SGID binaries
├── hashes/           # File hashes (MD5/SHA1/SHA256)
├── network/          # Network configuration and connections
├── hardware/         # Hardware information
├── auditd/           # Audit configuration (Linux)
├── virtual/          # Virtualization platform data
├── containers/       # Container runtime information
└── collector-*.txt   # Collection metadata
```

## 💻 System Requirements

### Minimal Requirements
- **Shell**: Any POSIX-compliant shell (/bin/sh)
- **Privileges**: Can run as normal user; root/sudo recommended for comprehensive collection
- **Tools**: Basic UNIX utilities (find, tar, grep) - standard on all UNIX systems
- **Space**: Enough space on the disk so logs and other files can be copied into single location (alternatively run from mounted disk or network partition). (varies by system size)

## ⚡ Performance & Limits

### Configurable Limits
- **File Size Cap**: 500MB default (prevents collecting large databases/media)
- **Smart Filtering**: Excludes virtual disk images (vmdk, vhd, ova)
- **Efficient Collection**: Uses rsync when available for faster copying

### Expected Run Times
- **Small Systems** (<10GB used): 5-10 minutes
- **Medium Systems** (10-100GB): 15-30 minutes
- **Large Systems** (100GB+): 30-60 minutes
- **Timeline Generation**: Adds 5-30 minutes depending on filesystem size

### Resource Usage
- **CPU**: Low to moderate (mainly during hashing)
- **Memory**: Minimal (<100MB typical)
- **Disk I/O**: Read-intensive during collection
- **Network**: None required

## 🎯 Use Cases

- **🚨 Incident Response**: Rapid forensic triage during security incidents
- **🔍 Compromise Assessment**: Identify indicators of system compromise
- **🛡️ Threat Hunting**: Collect artifacts for proactive threat detection
- **📊 Security Audits**: Document system state for compliance and analysis
- **🔬 Forensic Investigations**: Preserve evidence for detailed analysis
- **💾 System Baseline**: Create reference snapshots for change detection
- **🏢 Enterprise Security**: Deploy across internal networks for centralized collection
- **📱 IoT/Embedded Analysis**: Investigate compromised embedded devices

## 🌐 Deployment Scenarios

UNIX Collector excels in challenging environments where traditional forensic tools may not be viable:

- **Air-Gapped Networks**: No internet connectivity required
- **Restricted Environments**: No installation or compilation needed
- **Legacy Systems**: Works on older UNIX variants with basic shell
- **Embedded Devices**: Minimal footprint for resource-constrained systems
- **Containerized Environments**: Collects both host and container artifacts
- **Multi-Platform Infrastructure**: Single tool for heterogeneous environments

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests on the [GitHub repository](https://github.com/op7ic/unix_collector).

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## Acknowledgments

- Inspired by the collective knowledge of Portcullis Security Team
- Based on concepts from unix-privesc-check by pentestmonkey
- Special thanks to Ian Ventura-Whiting (Fizz) and Tim Brown (timb_machine) for inspiration

---

