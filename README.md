# unix_collector

A shell script for basic forensic collection of various artefacts from UNIX systems. ```unix_collector``` is a script that runs on various Unix systems and attempts to collect artefacts which could be analysed in attempt to identify potential system compromise. ```unix_collector``` is written as a single shell script so it can be easily uploaded and run (as opposed to un-tarred, compiled and installed). It can run either as a normal user or as root. It does a better job when running as root because it can read more files of course.


[![Imgur](https://i.imgur.com/6xMcGIg.gif)](#)

# Available platforms

* Sun Solaris
* Linux
* IBM AIX
* HPUX
* MacOS
* Debian
* Ubuntu
* CentOS
* Red Hat
* Android
* Vmware ESXi
* FreeBSD
* NetScaler
* OpenBSD
* Any IoT platform that is based on Linux/Unix
* Probably others as well.

# Features

* Runs everything from a single script
* No installation or external libraries needed
* Enumerate basic host information such as kernel version, processes, hostname and save details in output directory.
* Enumerate files written to the disk and create basic timeline using 'stat' command.
* Enumerate network information and save details in output directory.
* Enumerate patch and installed software information and save details in output directory.
* Enumerate process list and other process information and save details in output directory.
* Enumerate application lists, plist/apk for iOS/Android save them in output directory.
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
* Where copy or hashing operation happens, files over 500MB will be skipped. This default behaviour can be modified inside the script by changing RSYNC_MAX_FILESIZE, TAR_MAX_FILESIZE and HASH_MAX_FILESIZE global variables.
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
