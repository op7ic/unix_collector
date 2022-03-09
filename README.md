# unix_collector

A shell script for basic forensic collection of various artefacts from UNIX systems.

```unix_collector``` is a script that runs on Unix systems. It tries to hash files on the disk, grab logs and other important artefacts which could be analysed in attempt to identify potential system compromise.

```unix_collector``` is written as a single shell script so it can be easily uploaded and run (as opposed to un-tarred, compiled and installed). It can run either as a normal user or as root. It does a better job when running as root because it can read more files.

# Script Activities

* Enumerate basic host information such as kernel version, processes, hostname and save details in output directory.
* Enumerate network information and save details in output directory.
* Enumerate patch and installed software information and save details in output directory.
* Enumerate process list and other process information and save details in output directory.
* Hash files in various folders such as /home/ /opt/ /usr/ and save details in output directory.
* Hash files which are marked as SGID or SUID and save details in output directory.
* Copy various files such as cron job content into output directory.
* Copy SUID/SGID binaries into output directory.
* Copy system logs (i.e /var/log or /var/adm/) into output directory.
* TAR entire output directory and name it after hostname.

# Requirements

* Enough space on the disk so logs and other files can be copied into single location (alternatively run from mounted disk or network partition)
* Bash

# Examples 

Execute ```unix_collector``` without specifying any operating system version (script will guess OS type):

```chmod +x ./unix_collector && ./unix_collector```

Execute ```unix_collector``` on AIX while specifying platform:

```chmod +x ./unix_collector && ./unix_collector.sh --platform=aix```

# Available platforms

* Sun Solaris
* Linux
* IBM AIX
* HPUX
* Probably others as well.


# Sample Output
```

```
