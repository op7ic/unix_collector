# unix_collector

The unix_collector is a self-contained shell script designed for the forensic collection of various artifacts from Unix-based systems located deep inside internal network. It runs on multiple Unix platforms and gathers data that can be analyzed to identify potential system compromises.

As a single shell script, ```unix_collector``` is easy to upload and execute, without the need for untarring, compiling, installation, or an internet connection to download additional components. The script can be run either as a normal user or as root, though it performs more effectively when executed as root, as this allows it to access a wider range of system files and artifacts. 

📦 **9 Operating Systems** | 🐧 **8+ Linux Distros** | 🐳 **10 Container/VM Platforms** | 🔍 **Non-Invasive Collection**


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

> **Note**: The script automatically detects the platform and adjusts collection methods accordingly. For systems not explicitly listed, use the `--platform=generic` option for best-effort collection.


# Features

* Runs everything from a single script.
* No installation or external libraries needed.
* No internet connection needed.
* Enumerate basic host information such as kernel version, processes, hostname and save details in output directory.
* Enumerate files written to the disk and create basic timeline using 'stat' command.
* Enumerate network information and save details in output directory.
* Enumerate patch and installed software information and save details in output directory.
* Enumerate process list and other process information and save details in output directory.
* Enumerate application lists, plist/apk for iOS/Android save them in output directory.
* Enumerate hardware information.
* Enumerate virtual controller information (ESXi,VMBox,VIRT) and save details in output directory.
* Hash files in various folders such as /home/ /opt/ /usr/ and save details in output directory.
* Hash files which are marked as SGID or SUID and save details in output directory.
* Copy various files such as cron job, plist or other files into output directory.
* Copy SUID/SGID binaries into output directory.
* Copy home and tmp directories into output directory.
* Copy specific /proc/ files into output directory.
* Copy system logs (i.e /var/log or /var/adm/) into output directory.
* Copy /dev/shm into output directory.
* Gather information about containers.
* Where copy or hashing operation happens, files over 500MB will be skipped. This default behavior can be modified inside the script by changing RSYNC_MAX_FILESIZE, TAR_MAX_FILESIZE and HASH_MAX_FILESIZE global variables.
* TAR entire output directory and use hostname as file name with current date.

# Requirements

* Enough space on the disk so logs and other files can be copied into single location (alternatively run from mounted disk or network partition).
* sh

# Examples 

Execute ```unix_collector``` without specifying any operating system version (script will guess OS type):

```chmod +x ./unix_collector.sh && ./unix_collector.sh```

Execute ```unix_collector``` on AIX while specifying platform:

```chmod +x ./unix_collector.sh && ./unix_collector.sh --platform=aix```

Execute ```unix_collector``` on MacOS while specifying platform:

```chmod +x ./unix_collector.sh && ./unix_collector.sh --platform=mac```

# Sample Output
```

  _   _ _   _ _____  __   ____ ___  _     _     _____ ____ _____ ___  ____
 | | | | \ | |_ _\ \/ /  / ___/ _ \| |   | |   | ____/ ___|_   _/ _ \|  _ \
 | | | |  \| || | \  /  | |  | | | | |   | |   |  _|| |     | || | | | |_) |
 | |_| | |\  || | /  \  | |__| |_| | |___| |___| |__| |___  | || |_| |  _ <
  \___/|_| \_|___/_/\_\  \____\___/|_____|_____|_____\____| |_| \___/|_| \_\

A live forensic collection script for UNIX-like systems. Version: 1.7 by op7ic


PLATFORM: GNU/Linux

BASIC INFORMATION [0%  ]:
  > UNIX Collector
  > UNIX Collector Date
  > UNIX Collector User
  > UNIX Collector Platform
GENERAL INFORMATION [15%  ]:
  > Hostname
  > Kernel
  > Version
  > Check for tainted kernel
  > SSH settings
  > File timeline
  > Release
  > Kerberos ticket list
  > Full OS Info
  > Process list
  > Cron and other scheduler files
  > Kernel Modules
  > At scheduler
  > Kernel settings
  > Environment
  > ulimit
  > Auditd
  > spool files
INSTALLED SOFTWARE AND PATCHES [25% ]:
  > Installed software (this could take a few mins)
  > Installed patches
  > Compiler tools (NFS skip)
LOG, HOME and PROC FILE COLLECTION [50% ]:
  > Copying logs
  > Copying home dirs
  > Copying proc dirs
  > Copying /tmp/ and /var/tmp/ dirs where possible
SUID/SGID SEARCH [60% ]:
  > Finding all SUID/SGID binaries
HASH BINARIES [65% ]:
  > Hashing all SUID/SGID binaries
  > Hashing all HOME dirs
  > Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs
NETWORK INFORMATION [90% ]:
  > Interface configuration
  > IP addr
  > IP forwarding
  > Routing
  > Netstat
  > ARP cache
  > Hosts
  > DNS
  > TCP wrappers
  > RPC
  > IP Tables
  > IP Tables (IPv6)
FINISHING [100%]:
  > Removing empty files
  > Removing oversize file list
  > Creating TAR file
  > Removing temporary directory
```

# License

The unix_collector project uses the [GNU General Public License v3.0](LICENSE) software license.
