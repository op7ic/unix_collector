#!/bin/sh
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# Copyright (C) 2022  Jerzy 'Yuri' Kramarz (op7ic) 
# --------------------------------------------------
# A live forensic collection script for UNIX-like systems.
# Author: Jerzy 'Yuri' Kramarz (op7ic) 
# Inspired by: 
# - Collective knowledge of Portcullis Security Team. Check out https://labs.portcullis.co.uk/
# - https://github.com/pentestmonkey/unix-privesc-check/blob/master/upc.sh
# - Ian Ventura-Whiting (Fizz) 
# --------------------------------------------------
# This script is designed to work on multiple UNIX platforms
# and gather the information required for a quick forensic
# investigation of the device. 
# 
# Current UNIX platforms supported include:
#     > Sun Solaris
#     > Linux
#     > IBM AIX
#     > HPUX
#     > MacOS
#     > Debian
#     > Ubuntu
#     > CentOS
#     > Red Hat
#     > Android
#     > VMware ESXi
#     > FreeBSD
#     > OpenBSD
#     > NetScaler
#     > Any IoT platform that is based on Linux/Unix
#     > Probably others as well.
# 
# Commandline Options
# ~~~~~~~~~~~~~~~~~~~
#
#    --platform=<solaris | hpup | mac | aix | linux | android | generic>
#    Specify a platform, instead of using the platform auto-
#    detection code.
#
#    --quiet
#    No questions will be asked, unless specified


# ---------------------------
# Global Variables
# ---------------------------
VERSION="1.9"
HOSTNAME=`hostname`
PLATFORM="none"
SHORT_DATE=`date +%B" "%Y`
LONG_DATE=`date +%A" "%d" "%B" "%Y`
COLLECTION_DATE=`date +%d"-"%m"-"%Y`
WHOAMI="root"
QUIET="NO"
DISPLAYHELP="OFF"
OUTPUT_DIR="collector-${HOSTNAME}-${COLLECTION_DATE}"
TAR_FILE="collector-${HOSTNAME}-${COLLECTION_DATE}.tar"
RSYNC_MAX_FILESIZE=-500m
TAR_MAX_FILESIZE=-500M
HASH_MAX_FILESIZE=-500M
# ---------------------------
# Parse ARGS
# ---------------------------
for ARG in $*
do
    case $ARG in
        "--platform=solaris")
            PLATFORM="solaris"
            ;;
        "--platform=aix")
            PLATFORM="aix"
            ;;
        "--platform=mac")
            PLATFORM="mac"
            ;;
        "--platform=generic")
            PLATFORM="generic"
            ;;
        "--platform=linux")
            PLATFORM="linux"
            ;;
        "--platform=hpux")
            PLATFORM="hpux"
            ;;
        "--platform=android")
            PLATFORM="android"
            ;;
        "--quiet")
            QUIET="YES"
            ;;
    esac
done


# ---------------------------
# Detect Platform
# ---------------------------
if [ $PLATFORM = "none" ]
then
    if [ -x /usr/bin/showrev ]
    then
        PLATFORM="solaris"
    elif [ -x /usr/bin/lslpp ]
    then
        PLATFORM="aix"
    elif [ -x /usr/sbin/sam -o -x /usr/bin/sam ]
    then
        PLATFORM="hpux"
    elif [ -x /usr/bin/osacompile ]
    then
        PLATFORM="mac"
    elif [ -x /system/bin/app_process -o -x /system/bin/getprop ]
    then
        PLATFORM="android"
    elif [ -x /usr/bin/rpm -o -x /bin/rpm -o -x /usr/bin/dpkg -o -x /usr/bin/emerge ]
    then
        PLATFORM="linux"
    fi
fi

# ---------------------------
# Console Colors
# ---------------------------
if [ $PLATFORM != "hpux" ]
then
    esc="\033"
    RESET="${esc}[0m"         # DEFAULT
    COL_WARNING="${esc}[31m"  # RED
    COL_SECTION="${esc}[32m"  # BLUE
    COL_ENTRY="${esc}[34m"    # GREEN
    COL_LOGO="${esc}[36m"     # CYAN
else
    RESET=""
    COL_WARNING=""
    COL_SECTION=""
    COL_ENTRY=""
    COL_LOGO=""
fi

# ---------------------------
# Banner
# ---------------------------
echo "${COL_ENTRY}"
echo "  _   _ _   _ _____  __   ____ ___  _     _     _____ ____ _____ ___  ____   "
echo " | | | | \ | |_ _\ \/ /  / ___/ _ \| |   | |   | ____/ ___|_   _/ _ \|  _ \  "
echo " | | | |  \| || | \  /  | |  | | | | |   | |   |  _|| |     | || | | | |_) | "
echo " | |_| | |\  || | /  \  | |__| |_| | |___| |___| |__| |___  | || |_| |  _ <  "
echo "  \___/|_| \_|___/_/\_\  \____\___/|_____|_____|_____\____| |_| \___/|_| \_\ "
echo ""
echo "${COL_ENTRY}A live forensic collection script for UNIX-like systems. Version: $VERSION by op7ic"
echo ""
echo "${RESET}"

# ---------------------------
# Platform detected
# ---------------------------
case $PLATFORM in
    "solaris")
        echo "${COL_SECTION}PLATFORM:${RESET} Sun Solaris"
        ;;
    "linux")
        echo "${COL_SECTION}PLATFORM:${RESET} GNU/Linux"
        ;;
    "aix")
        echo "${COL_SECTION}PLATFORM:${RESET} IBM AIX"
        ;;
    "mac")
        echo "${COL_SECTION}PLATFORM:${RESET} MacOS (Darwin)"
        ;;
    "android")
        echo "${COL_SECTION}PLATFORM:${RESET} Android"
        ;;
    "hpux")
        echo "${COL_SECTION}PLATFORM:${RESET} HPUX"
        ;;
    *)
        PLATFORM="generic"
        echo "${COL_SECTION}PLATFORM:${RESET} Generic UNIX"
        ;;
esac
echo ""

# ---------------------------
# Check if directory exists
# ---------------------------
if [ -d $OUTPUT_DIR ]
then
    DELETEDIR="YES"

    if [ $QUIET = "NO" ]
    then
        echo "${COL_WARNING}The directory '$OUTPUT_DIR' already exists. Delete it?${RESET} [y] "
        read USERDIRCONFIRM
        if [ $USERDIRCONFIRM ]
        then
            if [ $USERDIRCONFIRM != "y" -a $USERDIRCONFIRM != "Y" ]
            then
                DELETEDIR="NO"
            fi
        fi
    fi

    if [ $DELETEDIR = "YES" ]
    then
        echo "Deleting existing output directory..."
        echo ""
        rm -fr $OUTPUT_DIR
    else
        echo "${COL_WARNING}Exiting...${RESET}"
        exit 1
    fi
fi

# ---------------------------
# check if TAR file exist
# ---------------------------
if [ -f $TAR_FILE ]
then
    DELETETAR="YES"

    if [ $QUIET = "NO" ]
    then
        echo "${COL_WARNING}The file '$TAR_FILE' already exists. Delete it?${RESET} [y] "
        read USERTARCONFIRM
        if [ $USERTARCONFIRM ]
        then
            if [ $USERTARCONFIRM != "y" -a $USERTARCONFIRM != "Y" ]
            then
                DELETETAR="NO"
            fi
        fi
    fi

    if [ $DELETETAR = "YES" ]
    then
        echo "Deleting existing tar file..."
        echo ""
        rm -f $TAR_FILE
    else
        echo "${COL_WARNING}Exiting...${RESET}"
        exit 1
    fi
fi

# Create output directory
mkdir $OUTPUT_DIR
# ------------------
# PART 2: THE BASICS
# ------------------
echo "${COL_SECTION}BASIC INFORMATION [0%  ]:${RESET}"
echo "  ${COL_ENTRY}>${RESET} UNIX Collector Version"
echo $VERSION 1> $OUTPUT_DIR/collector-version.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} UNIX Collector Date"
echo $LONG_DATE 1> $OUTPUT_DIR/collector-date.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} UNIX Collector User"
id 1> $OUTPUT_DIR/collector-user.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} UNIX Collector Platform"
echo $PLATFORM > $OUTPUT_DIR/collector-platform.txt

# ---------------------------
# PART 3: GENERAL INFORMATION
# ---------------------------

echo "${COL_SECTION}GENERAL INFORMATION [15%  ]:${RESET}"
mkdir $OUTPUT_DIR/general

echo "  ${COL_ENTRY}>${RESET} Hostname"
hostname 1> $OUTPUT_DIR/general/hostname.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Kernel"
uname -s 1> $OUTPUT_DIR/general/kernel.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Version"
uname -v 1> $OUTPUT_DIR/general/version.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Check for tainted kernel"
# Based on amazing work by Craig Rowland - https://twitter.com/CraigHRowland/status/1628883826738077696
cat /proc/sys/kernel/tainted 1> $OUTPUT_DIR/general/tainted_kernel.txt 2> /dev/null
for i in $(seq 18); do echo $(($i-1)) $(($(cat /proc/sys/kernel/tainted)>>($i-1)&1));done 1>> $OUTPUT_DIR/general/tainted_bitmap.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} SSH settings"
sshd -T 1> $OUTPUT_DIR/general/sshd-t.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} File timeline"
if [ $PLATFORM = "solaris" ]
then
    echo "Inode,Hard Link Count,Full Path,Last Access,Last Modification,Last Status Change,File Creation,User,Group,File Permissions,File Size(bytes)" > $OUTPUT_DIR/general/timeline.csv
    find / -xdev -print0 2>/dev/null | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 1>> $OUTPUT_DIR/general/timeline.csv 2>/dev/null
elif [ $PLATFORM = "linux" ]
then
    echo "Inode,Hard Link Count,Full Path,Last Access,Last Modification,Last Status Change,File Creation,User,Group,File Permissions,File Size(bytes)" > $OUTPUT_DIR/general/timeline.csv
    find / -xdev -print0 2>/dev/null | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 1>> $OUTPUT_DIR/general/timeline.csv 2>/dev/null
elif [ $PLATFORM = "android" ]
then
    echo "Inode,Hard Link Count,Full Path,Last Access,Last Modification,Last Status Change,File Creation,User,Group,File Permissions,File Size(bytes)" > $OUTPUT_DIR/general/timeline.csv
    find / -xdev -print0 2>/dev/null | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 1>> $OUTPUT_DIR/general/timeline.csv 2>/dev/null
elif [ $PLATFORM = "mac" ]
then
    find / -xdev -print0 2>/dev/null | xargs -0 stat -L 1>> $OUTPUT_DIR/general/timeline.txt 2>/dev/null
elif [ $PLATFORM = "generic" ]
then
    echo "Inode,Hard Link Count,Full Path,Last Access,Last Modification,Last Status Change,File Creation,User,Group,File Permissions,File Size(bytes)" > $OUTPUT_DIR/general/timeline.csv
    find / -xdev -print0 2>/dev/null | xargs -0 stat --printf="%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s\n" 1>> $OUTPUT_DIR/general/timeline.csv 2>/dev/null
elif [ $PLATFORM = "aix" ]
then
	echo "device number,inode,file name,nlink,uid,gid,rdev,size,access time,modified time,inode change time,io size,block size" > timeline.csv
	find / -xdev 2>/dev/null | perl -n -e '$_ =~ s/\x0a//g; $_ =~ s/\x0d//g;print $_ . "," . join(",", stat($_)) . "\n";' 1>> timeline.csv 2>/dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Release"
uname -r 1> $OUTPUT_DIR/general/release.txt 2> /dev/null
cp /etc/*release $OUTPUT_DIR/general/ 2> /dev/null
cp /etc/debian_version $OUTPUT_DIR/general/ 2> /dev/null

cp /etc/passwd $OUTPUT_DIR/general/ 2> /dev/null
cp /etc/group $OUTPUT_DIR/general/ 2> /dev/null
cp /etc/ssh/sshd_config $OUTPUT_DIR/general/ 2> /dev/null
cp /etc/ssh/ssh_config $OUTPUT_DIR/general/ 2> /dev/null
zdump /etc/localtime 1> $OUTPUT_DIR/general/timezone.txt 2> /dev/null
stat /lost+found 1> $OUTPUT_DIR/general/installation-time.txt 2> /dev/null
ls -lct /etc | tail -1 1> $OUTPUT_DIR/general/installation-time.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Kerberos ticket list"
klist 1> $OUTPUT_DIR/general/kerberos-ticket-list.txt 2> /dev/null
echo "  ${COL_ENTRY}>${RESET} Mount points"
mount 1> $OUTPUT_DIR/general/mount.txt 2> /dev/null

if [ $PLATFORM = "android" ]
then
    echo "  ${COL_ENTRY}>${RESET} Android Features"
    pm list features 1> $OUTPUT_DIR/general/pm_list_features.txt 2> /dev/null
    echo "  ${COL_ENTRY}>${RESET} Android Users"
    pm list users 1> $OUTPUT_DIR/general/android_users.txt 2> /dev/null
    echo "  ${COL_ENTRY}>${RESET} Android Properties"
    getprop 1> $OUTPUT_DIR/general/android_getprop.txt 2> /dev/null
    getprop -T 1> $OUTPUT_DIR/general/android_getprop-T.txt 2> /dev/null
    getprop -Z 1> $OUTPUT_DIR/general/android_getprop-Z.txt 2> /dev/null
    lsof -l 1> $OUTPUT_DIR/general/android_lsof_l.txt 2> /dev/null
fi
echo "  ${COL_ENTRY}>${RESET} LSOF"
lsof -nPl 1> $OUTPUT_DIR/general/lsof_nPl.txt 2> /dev/null

if [ $PLATFORM = "aix" ]
then
    echo "  ${COL_ENTRY}>${RESET} Processor"
    uname -p 1> $OUTPUT_DIR/general/processor.txt 2> /dev/null
    oslevel -s 1> $OUTPUT_DIR/general/oslevel.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Full OS Info"
uname -a 1> $OUTPUT_DIR/general/uname-a.txt 2> /dev/null

if [ $PLATFORM = "solaris" ]
then
    echo "  ${COL_ENTRY}>${RESET} EEPROM"
    eeprom 1> $OUTPUT_DIR/general/eeprom.txt 2> /dev/null
fi


echo "  ${COL_ENTRY}>${RESET} Stroage Info"
arcstat 1> $OUTPUT_DIR/general/storage_arcstat.txt 2> /dev/null
blkid 1> $OUTPUT_DIR/general/storage_blkid.txt 2> /dev/null
df 1> $OUTPUT_DIR/general/storage_df.txt 2> /dev/null
df -h 1> $OUTPUT_DIR/general/storage_df_h.txt 2> /dev/null
df -n 1> $OUTPUT_DIR/general/storage_df_n.txt 2> /dev/null
diskutil list 1> $OUTPUT_DIR/general/storage_diskutil.txt 2> /dev/null
fdisk -l 1> $OUTPUT_DIR/general/storage_fdisk.txt 2> /dev/null
findmnt --ascii 1> $OUTPUT_DIR/general/storage_findmnt.txt 2> /dev/null
geom disk list 1> $OUTPUT_DIR/general/storage_geom_disk_list.txt 2> /dev/null
geom -t 1> $OUTPUT_DIR/general/storage_geom_t.txt 2> /dev/null
gstat -b  1> $OUTPUT_DIR/general/storage_gstat_b.txt 2> /dev/null
iostat -d -l 1> $OUTPUT_DIR/general/storage_iostat_d_l.txt 2> /dev/null
iscsiadm -m node 1> $OUTPUT_DIR/general/storage_iscsiadm_node.txt 2> /dev/null
iscsiadm -s 1> $OUTPUT_DIR/general/storage_iscsiadm_s.txt 2> /dev/null
lparstat -i 1> $OUTPUT_DIR/general/storage_lparstat.txt 2> /dev/null
ls -l /dev/disk/by-* 1> $OUTPUT_DIR/general/storage_disks_dev.txt 2> /dev/null
ls -l /vmfs/devices/disks 1> $OUTPUT_DIR/general/storage_disks_vmfs.txt 2> /dev/null
lsblk 1> $OUTPUT_DIR/general/storage_lsblk.txt 2> /dev/null
lsblk -l 1> $OUTPUT_DIR/general/storage_lsblk_l.txt 2> /dev/null
lsblk -f 1> $OUTPUT_DIR/general/storage_lsblk_f.txt 2> /dev/null
lsfs 1> $OUTPUT_DIR/general/storage_lsfs.txt 2> /dev/null
lspv 1> $OUTPUT_DIR/general/storage_lspv.txt 2> /dev/null
lsvg 1> $OUTPUT_DIR/general/storage_lsvg.txt 2> /dev/null
lvdisplay 1> $OUTPUT_DIR/general/storage_lvdisplay.txt 2> /dev/null
lvs 1> $OUTPUT_DIR/general/storage_lvs.txt 2> /dev/null
cat /proc/mdstat 1> $OUTPUT_DIR/general/storage_mdstat.txt 2> /dev/null
mdadm --detail --scan --verbose 1> $OUTPUT_DIR/general/storage_mdadm.txt 2> /dev/null
mount 1> $OUTPUT_DIR/general/storage_mount.txt 2> /dev/null
pdisk -l 1> $OUTPUT_DIR/general/storage_pdisk.txt 2> /dev/null
pvdisplay 1> $OUTPUT_DIR/general/storage_pvdisplay.txt 2> /dev/null
pvesm status 1> $OUTPUT_DIR/general/storage_pvesm.txt 2> /dev/null
pvs 1> $OUTPUT_DIR/general/storage_pvs.txt 2> /dev/null
vgdisplay 1> $OUTPUT_DIR/general/storage_vgdisplay.txt 2> /dev/null
vgs 1> $OUTPUT_DIR/general/storage_vgs.txt 2> /dev/null
zfs list -o name,avail,used,usedsnap,usedds,usedrefreserv,usedchild,sharenfs,mountpoint 1> $OUTPUT_DIR/general/storage_zfs_list.txt 2> /dev/null
zpool history 1> $OUTPUT_DIR/general/storage_zpool_history.txt 2> /dev/null
zpool list -v 1> $OUTPUT_DIR/general/storage_zpool_list.txt 2> /dev/null
zpool status -v 1> $OUTPUT_DIR/general/storage_zpool_status.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Process list and information" 
ps -efl 1> $OUTPUT_DIR/general/ps.txt 2> /dev/null
ps -auxww 1> $OUTPUT_DIR/general/ps-auxww.txt 2> /dev/null
ps -deaf 1> $OUTPUT_DIR/general/ps-deaf.txt 2> /dev/null
ps -aux 1> $OUTPUT_DIR/general/ps-aux.txt 2> /dev/null
pstree 1> $OUTPUT_DIR/general/pstree.txt 2> /dev/null
pstree -a 1> $OUTPUT_DIR/general/pstree_a.txt 2> /dev/null
pstree -p -n 1> $OUTPUT_DIR/general/pstree_p_n.txt 2> /dev/null
ps -eo args | grep "^/" | awk '{print $1}' | sort -u 1> $OUTPUT_DIR/general/running_executables.txt 2> /dev/null
ps -c | awk '{print $4}' | sort -u | grep "^/" 1> $OUTPUT_DIR/general/running_executables_esxi.txt 2> /dev/null

mkdir $OUTPUT_DIR/process_info/ 2> /dev/null
for pid in /proc/[0-9]*; do echo "PID: $(echo ${pid} | sed -e 's:/proc/::')" 2> /dev/null && ls -la /proc/$(echo ${pid} | sed -e 's:/proc/::')/fd; done 1> $OUTPUT_DIR/process_info/all_process_handles.txt 2> /dev/null
ls -l /proc/[0-9]*/cwd 1> $OUTPUT_DIR/process_info/process_working_directory.txt 2> /dev/null
ls -l /proc/[0-9]*/exe 2> /dev/null | grep -E "\(deleted\)" | awk -F"/proc/|/exe" '{print $2}' 1> $OUTPUT_DIR/process_info/deleted_processes_ids.txt 2> /dev/null
ls -l /proc/[0-9]*/exe 2> /dev/null | grep -E "\(deleted\)" 1> $OUTPUT_DIR/process_info/deleted_processes.txt 2> /dev/null
for pid in $(find /proc -maxdepth 1 -type d -name '[0-9]*'); do echo $(basename $pid); done 1> $OUTPUT_DIR/process_info/all_process_ids.txt 2> /dev/null


if [ $PLATFORM = "generic" ]
then
	find /proc/[0-9]*/exe -type l -exec sha256sum {} \; >> $OUTPUT_DIR/process_info/sha256sum_running_processes_proc_exe 2> /dev/null
	find /proc/[0-9]*/file -type l -exec sha256sum {} \; >> $OUTPUT_DIR/process_info/sha256sum_running_processes_proc_file 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec sha1sum {} \; >> $OUTPUT_DIR/process_info/sha1sum_running_processes_proc_exe 2> /dev/null
	find /proc/[0-9]*/file -type l -exec sha1sum {} \; >> $OUTPUT_DIR/process_info/sha1sum_running_processes_proc_file 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec md5sum {} \; >> $OUTPUT_DIR/process_info/md5sum_running_processes_proc_exe 2> /dev/null
	find /proc/[0-9]*/file -type l -exec md5sum {} \; >> $OUTPUT_DIR/process_info/md5sum_running_processes_proc_file 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec openssl dgst -sha256 {} \; >> $OUTPUT_DIR/process_info/openssl_sha256_running_processes_proc_exe 2> /dev/null
	find /proc/[0-9]*/file -type l -exec openssl dgst -sha256 {} \; >> $OUTPUT_DIR/process_info/openssl_sha256_running_processes_proc_file 2> /dev/null
	ps -axo args | grep "^/" | awk '{print $1}' | sort -u | xargs -I {} shasum -a 256 {} >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	ps -axo args | grep "^/" | awk '{print $1}' | sort -u | xargs -I {} shasum -a 1 {} >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	ps -axo comm | grep "^/" | sort -u | xargs -I {} md5 -q {} >> $OUTPUT_DIR/process_info/md5sum_running_processes 2> /dev/null
	ps -axo args | grep ^/ | awk '{print $1}' | sort -u 1> $OUTPUT_DIR/process_info/process_running_paths.txt 2> /dev/null
fi

if [ $PLATFORM = "linux" ]
then
	find /proc/[0-9]*/exe -type l -exec sha256sum {} \; >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec sha1sum {} \; >> $OUTPUT_DIR/process_info/sha1sum_running_processes 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec md5sum {} \; >> $OUTPUT_DIR/process_info/md5sum_running_processes 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec openssl dgst -sha256 {} \; >> $OUTPUT_DIR/process_info/openssl_sha256_running_processes 2> /dev/null
fi

if [ $PLATFORM = "aix" ]
then
	find /proc/[0-9]*/object/a.out -type l -exec sha256sum {} \; >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	find /proc/[0-9]*/object/a.out -type l -exec sha1sum {} \; >> $OUTPUT_DIR/process_info/sha1sum_running_processes 2> /dev/null
	find /proc/[0-9]*/object/a.out -type l -exec md5sum {} \; >> $OUTPUT_DIR/process_info/md5sum_running_processes 2> /dev/null
	find /proc/[0-9]*/object/a.out -type l -exec openssl dgst -sha256 {} \; >> $OUTPUT_DIR/process_info/openssl_sha256_running_processes 2> /dev/null
fi

if [ $PLATFORM = "solaris" ]
then
	find /proc/[0-9]*/path/a.out -type l -exec sha256sum {} \; >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	find /proc/[0-9]*/path/a.out -type l -exec sha1sum {} \; >> $OUTPUT_DIR/process_info/sha1sum_running_processes 2> /dev/null
	find /proc/[0-9]*/path/a.out -type l -exec md5sum {} \; >> $OUTPUT_DIR/process_info/md5sum_running_processes 2> /dev/null
	find /proc/[0-9]*/path/a.out -type l -exec openssl dgst -sha256 {} \; >> $OUTPUT_DIR/process_info/openssl_sha256_running_processes 2> /dev/null
fi

if [ $PLATFORM = "hpux" ]
then
	find /proc/[0-9]*/exe -type l -exec sha256sum {} \; >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec sha1sum {} \; >> $OUTPUT_DIR/process_info/sha1sum_running_processes 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec md5sum {} \; >> $OUTPUT_DIR/process_info/md5sum_running_processes 2> /dev/null
	find /proc/[0-9]*/exe -type l -exec openssl dgst -sha256 {} \; >> $OUTPUT_DIR/process_info/openssl_sha256_running_processes 2> /dev/null
fi

if [ $PLATFORM = "mac" ]
then

	ps -axo comm | grep "^/" | sort -u | xargs -I {} shasum -a 256 {} >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	ps -axo comm | grep "^/" | sort -u | xargs -I {} shasum -a 1 {} >> $OUTPUT_DIR/process_info/sha1sum_running_processes 2> /dev/null
	ps -axo comm | grep "^/" | sort -u | xargs -I {} md5 -q {} >> $OUTPUT_DIR/process_info/md5sum_running_processes 2> /dev/null
fi


if [ $PLATFORM = "solaris" ]
then
	ptree 1> $OUTPUT_DIR/general/ptree.txt 2> /dev/null
fi

if [ $PLATFORM = "aix" ]
then
	proctree -a 1> $OUTPUT_DIR/general/proctree_a.txt 2> /dev/null
	pstat -a 1> $OUTPUT_DIR/general/pstat_a.txt 2> /dev/null
	pstat -f 1> $OUTPUT_DIR/general/pstat_f.txt 2> /dev/null
	pstat -A 1> $OUTPUT_DIR/general/pstat_A.txt 2> /dev/null
	pstat -p 1> $OUTPUT_DIR/general/pstat_p.txt 2> /dev/null
fi

if [ $PLATFORM = "android" ]
then
	ps -A 1> $OUTPUT_DIR/general/android_ps-all 2> /dev/null
	ps -A -f -l 1> $OUTPUT_DIR/general/android_ps-all-F-l 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Cron and other scheduler files"
if [ -f "/etc/crontab" ] && [ -r "/etc/crontab" ]; then
	cp /etc/crontab $OUTPUT_DIR/general/etc-crontab.txt 2>/dev/null
fi

mkdir $OUTPUT_DIR/general/crontabs/ 2> /dev/null

if [ -d /var/cron/ ]
then
	cp -R /var/cron/ $OUTPUT_DIR/general/crontabs/var_cron 2> /dev/null
fi

if [ -d /var/adm/cron/ ]
then
	cp -R /var/adm/cron/ $OUTPUT_DIR/general/crontabs/var_adm_cron 2> /dev/null
fi

if [ -d /var/spool/at/ ]
then
	cp -R /var/spool/at/ $OUTPUT_DIR/general/crontabs/var_spool_at 2> /dev/null
fi

if [ -d /var/spool/cron/ ]
then
	cp -R /var/spool/cron/ $OUTPUT_DIR/general/crontabs/var_spool_cron 2> /dev/null
fi

if [ -d /data/crontab/ ]
then
	cp -R /data/crontab/ $OUTPUT_DIR/general/crontabs/ 2> /dev/null
fi

if [ -d /dev/shm/ ]
then
	cp -R /dev/shm/ $OUTPUT_DIR/general/dev_shm_folder/ 2> /dev/null
fi

if [ -d /run/shm ]
then
	cp -R /run/shm/ $OUTPUT_DIR/general/run_shm_folder/ 2> /dev/null
fi


if [ $PLATFORM = "mac" ]
then
    crontab -v 1> $OUTPUT_DIR/general/crontab-v.txt 2> /dev/null
	crontab -l 1> $OUTPUT_DIR/general/crontab-l.txt 2> /dev/null
	cp -R /var/at/ $OUTPUT_DIR/general/crontabs/var_at 2> /dev/null
	cp -R /private/var/at/tabs/ $OUTPUT_DIR/general/crontabs/private_var_at_tabs 2> /dev/null
	cp -R /Library/StartupItems/ $OUTPUT_DIR/general/crontabs/StartupItems 2> /dev/null
	cp -R /System/Library/StartupItems/ $OUTPUT_DIR/general/crontabs/System_StartupItems 2> /dev/null
	cp -R /Library/LaunchAgents/ $OUTPUT_DIR/general/crontabs/LaunchAgents 2> /dev/null
	cp -R /System/Library/LaunchAgents/ $OUTPUT_DIR/general/crontabs/System_LaunchAgents 2> /dev/null
	cp -R /usr/lib/cron/jobs/ $OUTPUT_DIR/general/crontabs/usr_lib_cron_jobs 2> /dev/null
	cp -R /usr/lib/cron/tabs/ $OUTPUT_DIR/general/crontabs/usr_lib_cron_tabs 2> /dev/null
	cp /etc/periodic.conf $OUTPUT_DIR/general/crontabs/ 2> /dev/null
	cp /etc/periodic.conf.local $OUTPUT_DIR/general/crontabs/ 2> /dev/null
	cp -R /etc/periodic/ $OUTPUT_DIR/general/crontabs/ 2> /dev/null
	cp -R /etc/daily.local/ $OUTPUT_DIR/general/crontabs/ 2> /dev/null
	cp -R /etc/weekly.local/ $OUTPUT_DIR/general/crontabs/ 2> /dev/null
	cp -R /etc/monthly.local/ $OUTPUT_DIR/general/crontabs/ 2> /dev/null
	cp -R /etc/periodic/daily/ $OUTPUT_DIR/general/crontabs/periodic_daily 2> /dev/null
	cp -R /etc/periodic/weekly/ $OUTPUT_DIR/general/crontabs/periodic_weekly 2> /dev/null
	cp -R /etc/periodic/monthly/ $OUTPUT_DIR/general/crontabs/periodic_monthly 2> /dev/null
	cp -R /usr/local/etc/periodic/ $OUTPUT_DIR/general/crontabs/usr_local_etc_periodic 2> /dev/null
	cp -R /etc/crontab $OUTPUT_DIR/general/crontabs/etc_crontab 2> /dev/null
	cp -R /Library/LaunchDaemons/ $OUTPUT_DIR/general/crontabs/LaunchDaemons 2> /dev/null
	cp -R /System/Library/LaunchDaemons/ $OUTPUT_DIR/general/crontabs/System_LaunchDaemons 2> /dev/null
fi

if [ $PLATFORM = "android" ]
then
	crontab -l 1> $OUTPUT_DIR/general/android_crontab-l 2> /dev/null
fi

mkdir $OUTPUT_DIR/general/systemd/ 2> /dev/null 
if [ -d /lib/systemd/system/ ]
then
	cp -R /lib/systemd/system/ $OUTPUT_DIR/general/systemd/lib_systemd_system 2> /dev/null
fi

if [ -d /usr/lib/systemd/system/ ]
then
	cp -R /usr/lib/systemd/system/ $OUTPUT_DIR/general/systemd/usr_lib_systemd_system 2> /dev/null
fi

if [ $PLATFORM = "aix" ]
then
    crontab -v 1> $OUTPUT_DIR/general/crontab.txt 2> /dev/null
else
    crontab -l 1> $OUTPUT_DIR/general/crontab.txt 2> /dev/null
fi
if [ -d /var/spool/cron/crontabs ]
then
    mkdir $OUTPUT_DIR/general/crontabs 2> /dev/null
    for name in `ls /var/spool/cron/crontabs/`
    do
        ls -lL /var/spool/cron/crontabs/$name 1>> $OUTPUT_DIR/general/crontabs/perms 2> /dev/null
        cp /var/spool/cron/crontabs/$name $OUTPUT_DIR/general/crontabs/$name 2> /dev/null
	cat /var/spool/cron/crontabs/$name 2> /dev/null | grep -v "^#" | while read null null null null null name null
	do
	    ls -lL $name 1>> $OUTPUT_DIR/general/crontabs/perms 2> /dev/null
	done
    done
fi
if [ -d /etc/cron.d ]
then
    mkdir $OUTPUT_DIR/general/cron.d 2> /dev/null
    for name in `ls /etc/cron.d/`
    do
        if [ -f /etc/cron.d/$name ]
        then
	        ls -lL /etc/cron.d/$name 1>> $OUTPUT_DIR/general/cron.d/perms 2> /dev/null
            cp /etc/cron.d/$name $OUTPUT_DIR/general/cron.d/$name 2> /dev/null
	    if [ $PLATFORM = "linux" ]
	    then
		cat /etc/cron.d/$name 2> /dev/null | grep -v "^#" | while read null null null null null user name null
		do
		    echo "$user:" 1>> $OUTPUT_DIR/general/cron.d/perms 2> /dev/null
		    ls -lL /etc/cron.d/$name 1>> $OUTPUT_DIR/general/cron.d/perms 2> /dev/null
		done
	    fi
        fi
    done
fi
if [ -d /etc/cron.hourly ]
then
    mkdir $OUTPUT_DIR/general/cron.hourly 2> /dev/null
    for name in `ls /etc/cron.hourly/` 
    do
        if [ -f /etc/cron.hourly/$name ]
        then
	        ls -lL /etc/cron.d/$name 1>> $OUTPUT_DIR/general/cron.d/perms 2> /dev/null
            cp /etc/cron.hourly/$name $OUTPUT_DIR/general/cron.hourly/$name 2> /dev/null
        fi
    done
fi
if [ -d /etc/cron.daily ]
then
    mkdir $OUTPUT_DIR/general/cron.daily 2> /dev/null
    for name in `ls /etc/cron.daily/` 
    do
        if [ -f /etc/cron.daily/$name ]
        then
	        ls -lL /etc/cron.daily/$name 1>> $OUTPUT_DIR/general/cron.daily/perms 2> /dev/null
            cp /etc/cron.daily/$name $OUTPUT_DIR/general/cron.daily/$name 2> /dev/null
        fi
    done
fi
if [ -d /etc/cron.weekly ]
then
    mkdir $OUTPUT_DIR/general/cron.weekly 2> /dev/null
    for name in `ls /etc/cron.weekly/`
    do
        if [ -f /etc/cron.weekly/$name ]
        then
	        ls -lL /etc/cron.weekly/$name 1>> $OUTPUT_DIR/general/cron.weekly/perms 2> /dev/null
            cp /etc/cron.weekly/$name $OUTPUT_DIR/general/cron.weekly/$name 2> /dev/null
        fi
    done
fi
if [ -d /etc/cron.monthly ]
then
    mkdir $OUTPUT_DIR/general/cron.monthly 2> /dev/null
    for name in `ls /etc/cron.monthly/`
    do
        if [ -f /etc/cron.monthly/$name ]
        then
	        ls -lL /etc/cron.monthly/$name 1>> $OUTPUT_DIR/general/cron.monthly/perms 2> /dev/null
            cp /etc/cron.monthly/$name $OUTPUT_DIR/general/cron.monthly/$name 2> /dev/null
        fi
    done
fi

echo "  ${COL_ENTRY}>${RESET} Kernel Modules"
if [ $PLATFORM = "solaris" ]
then
    modinfo 1> $OUTPUT_DIR/general/kernel-modules.txt 2> /dev/null
elif [ $PLATFORM = "linux" ]
then
    lsmod 1> $OUTPUT_DIR/general/kernel-modules.txt 2> /dev/null
elif [ $PLATFORM = "android" ]
then
    lsmod 1> $OUTPUT_DIR/general/kernel-modules.txt 2> /dev/null
elif [ $PLATFORM = "mac" ]
then
	kmutil showloaded 1> $OUTPUT_DIR/general/kernel-modules.txt 2> /dev/null
elif [ $PLATFORM = "android" ]
then
	ls -la /sys/module/ 1> $OUTPUT_DIR/general/kernel-modules.txt 2> /dev/null
	ls -la /system/lib/modules/ 1> $OUTPUT_DIR/general/loadable-modules.txt 2> /dev/null
elif [ $PLATFORM = "aix" ]
then
	genkex 1> $OUTPUT_DIR/general/kernel-modules.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} At scheduler"
if [ $PLATFORM != "solaris" ]
then
    atq 1> $OUTPUT_DIR/general/atq.txt 2> /dev/null
fi
if [ -d /var/spool/cron/atjobs ]
then
    mkdir $OUTPUT_DIR/general/atjobs 2> /dev/null
    for name in `ls /var/spool/cron/atjobs/`
    do
        cp /var/spool/cron/atjobs/$name $OUTPUT_DIR/general/atjobs/$name 2> /dev/null
    done
fi

echo "  ${COL_ENTRY}>${RESET} Kernel settings"
cat /etc/sysctl.conf 1> $OUTPUT_DIR/general/sysctl.conf 2> /dev/null
if [ $PLATFORM = "linux" ]
then
    sysctl -a 1> $OUTPUT_DIR/general/sysctl-a.txt 2> /dev/null
fi
if [ $PLATFORM = "android" ]
then
    sysctl -a 1> $OUTPUT_DIR/general/sysctl-a.txt 2> /dev/null
fi
if [ $PLATFORM = "mac" ]
then
    sysctl -a 1> $OUTPUT_DIR/general/sysctl-a.txt 2> /dev/null
fi
if [ $PLATFORM = "solaris" ]
then
    cat /etc/system 1> $OUTPUT_DIR/general/system 2> /dev/null
    ndd /dev/ip \? | while read setting null
    do
    	echo "$setting" 1>> $OUTPUT_DIR/general/ip 2> /dev/null
	ndd /dev/ip $setting 1>> $OUTPUT_DIR/general/ip 2> /dev/null
    done 
fi

echo "  ${COL_ENTRY}>${RESET} Environment"
env 1> $OUTPUT_DIR/general/env.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} ulimit"
ulimit -a 1> $OUTPUT_DIR/general/ulimit-a.txt 2> /dev/null

if [ $PLATFORM = "solaris" ]
then
    echo "  ${COL_ENTRY}>${RESET} Zones"
    zoneadm list -i -v 1> $OUTPUT_DIR/general/zoneadm_list.txt 2> /dev/null
fi

if [ $PLATFORM = "linux" ]
then
    echo "  ${COL_ENTRY}>${RESET} Auditd"
    mkdir $OUTPUT_DIR/auditd
    auditctl -l > $OUTPUT_DIR/auditd/auditctl-l.txt 2> /dev/null
    auditctl -s > $OUTPUT_DIR/auditd/auditctl-s.txt 2> /dev/null
    cp /etc/audit/audit.rules $OUTPUT_DIR/auditd/ 2> /dev/null
    cp /etc/audit/auditd.conf $OUTPUT_DIR/auditd/ 2> /dev/null
    ps aux | grep auditd > $OUTPUT_DIR/auditd/ps-grep-auditd.txt 2> /dev/null
    mkdir $OUTPUT_DIR/selinux
    sestatus -v > $OUTPUT_DIR/selinux/sestatus-v.txt 2> /dev/null
    cp /etc/selinux/config $OUTPUT_DIR/selinux/ 2> /dev/null
    cp /etc/sysconfig/selinux $OUTPUT_DIR/selinux/sysconfig-selinux 2> /dev/null
fi

if [ $PLATFORM = "mac" ]
then
	cp /etc/security/audit_control $OUTPUT_DIR/auditd/ 2> /dev/null
	cp /var/audit/ $OUTPUT_DIR/auditd/ 2> /dev/null
	
fi

echo "  ${COL_ENTRY}>${RESET} spool files"
mkdir $OUTPUT_DIR/general/spool/ 2> /dev/null
cp -R /var/spool $OUTPUT_DIR/general/spool/ 2> /dev/null
if [ $PLATFORM = "mac" ]
then
	mkdir $OUTPUT_DIR/general/spool/private_var_spool/ 2> /dev/null
	cp -R /private/var/spool/ $OUTPUT_DIR/general/spool/private_var_spool/ 2> /dev/null
fi


echo "  ${COL_ENTRY}>${RESET} Hardware information"
mkdir $OUTPUT_DIR/hardware/ 2> /dev/null

if [ $PLATFORM = "linux" ]
then
    cat /proc/cpuinfo 1> $OUTPUT_DIR/hardware/cpuinfo.txt 2> /dev/null
	dmesg 1> $OUTPUT_DIR/hardware/dmesg.txt 2> /dev/null
	dmesg -a 1> $OUTPUT_DIR/hardware/dmesg_a.txt 2> /dev/null
	dmesg -s 1> $OUTPUT_DIR/hardware/dmesg_s.txt 2> /dev/null
	dmidecode 1> $OUTPUT_DIR/hardware/dmidecode.txt 2> /dev/null
	hwinfo 1> $OUTPUT_DIR/hardware/hwinfo.txt 2> /dev/null
	lscpu 1> $OUTPUT_DIR/hardware/lscpu.txt 2> /dev/null
	lshw 1> $OUTPUT_DIR/hardware/lshw.txt 2> /dev/null
	lspci 1> $OUTPUT_DIR/hardware/lspci.txt 2> /dev/null
	lspci -vv 1> $OUTPUT_DIR/hardware/lspci_vv.txt 2> /dev/null
	lspci -nn -k 1> $OUTPUT_DIR/hardware/lspci_nn_k.txt 2> /dev/null
	lsscsi 1> $OUTPUT_DIR/hardware/lsscsi.txt 2> /dev/null
	lshal 1> $OUTPUT_DIR/hardware/lshal.txt 2> /dev/null
	lsusb 1> $OUTPUT_DIR/hardware/lsusb.txt 2> /dev/null
	lsusb -vv 1> $OUTPUT_DIR/hardware/lsusb_vv.txt 2> /dev/null
	lshw -businfo 1> $OUTPUT_DIR/hardware/lshw_businfo.txt 2> /dev/null
	lspci -vvknnqq 1> $OUTPUT_DIR/hardware/lspci_vvknnqq.txt 2> /dev/null
fi
if [ $PLATFORM = "android" ]
then
    dmesg 1> $OUTPUT_DIR/hardware/dmesg.txt 2> /dev/null
fi
if [ $PLATFORM = "mac" ]
then
    dmesg 1> $OUTPUT_DIR/hardware/dmesg.txt 2> /dev/null
	hostinfo 1> $OUTPUT_DIR/hardware/hostinfo.txt 2> /dev/null
	ioreg -l 1> $OUTPUT_DIR/hardware/ioreg.txt 2> /dev/null
	nvram -p 1> $OUTPUT_DIR/hardware/nvram_p.txt 2> /dev/null
	systemstats 1> $OUTPUT_DIR/hardware/systemstats.txt 2> /dev/null
fi
if [ $PLATFORM = "solaris" ]
then
    cfgadm -l 1> $OUTPUT_DIR/hardware/cfgadm.txt 2> /dev/null
	dmesg 1> $OUTPUT_DIR/hardware/dmesg.txt 2> /dev/null
	dmesg -a 1> $OUTPUT_DIR/hardware/dmesg_a.txt 2> /dev/null
	dmesg -s 1> $OUTPUT_DIR/hardware/dmesg_s.txt 2> /dev/null
	prtconf -v 1> $OUTPUT_DIR/hardware/prtconf.txt 2> /dev/null
	psrinfo -v 1> $OUTPUT_DIR/hardware/psrinfo.txt 2> /dev/null
	smbios 1> $OUTPUT_DIR/hardware/smbios.txt 2> /dev/null
fi
if [ $PLATFORM = "aix" ]
then
    alog -o -t boot 1> $OUTPUT_DIR/hardware/alog_boot.txt 2> /dev/null
	bootlist -o -m normal 1> $OUTPUT_DIR/hardware/bootlist.txt 2> /dev/null
	lsdev -P 1> $OUTPUT_DIR/hardware/lsdev.txt 2> /dev/null
	mpstat 1> $OUTPUT_DIR/hardware/mpstat.txt 2> /dev/null
	prtconf -v 1> $OUTPUT_DIR/hardware/prtconf.txt 2> /dev/null
fi
if [ $PLATFORM = "hpux" ]
then
    machinfo 1> $OUTPUT_DIR/hardware/machinfo.txt 2> /dev/null
	lsdev 1> $OUTPUT_DIR/hardware/lsdev.txt 2> /dev/null
	ioscan -kfnC disk 1> $OUTPUT_DIR/hardware/ioscan_disk.txt 2> /dev/null
	isocan -kfnC tape 1> $OUTPUT_DIR/hardware/ioscan_tape.txt 2> /dev/null
	ioscan -kfnC lan 1> $OUTPUT_DIR/hardware/ioscan_lan.txt 2> /dev/null
	ioscan -kfnC fc 1> $OUTPUT_DIR/hardware/ioscan_fibre_channel.txt 2> /dev/null
	ioscan -kfnC processor 1> $OUTPUT_DIR/hardware/ioscan_processor.txt 2> /dev/null
	/opt/ignite/bin/print_manifest  1> $OUTPUT_DIR/hardware/print_manifest.txt 2> /dev/null
	echo "selall;info;wait;infolog" | /usr/sbin/cstm 1> $OUTPUT_DIR/hardware/cstm_hardwareinfo.txt 2> /dev/null
	echo "selclass qualifier memory;info;wait;infolog"|cstm 1> $OUTPUT_DIR/hardware/cstm_memoryinfo.txt 2> /dev/null
	lssf 1> $OUTPUT_DIR/hardware/lssf.txt 2> /dev/null
	
fi
if [ $PLATFORM = "generic" ]
then
	dmesg 1> $OUTPUT_DIR/hardware/dmesg.txt 2> /dev/null
	dmesg -a 1> $OUTPUT_DIR/hardware/dmesg_a.txt 2> /dev/null
	dmesg -s 1> $OUTPUT_DIR/hardware/dmesg_s.txt 2> /dev/null
	hwinfo 1> $OUTPUT_DIR/hardware/hwinfo.txt 2> /dev/null
	lscpu 1> $OUTPUT_DIR/hardware/lscpu.txt 2> /dev/null
	lshw 1> $OUTPUT_DIR/hardware/lshw.txt 2> /dev/null
	lspci 1> $OUTPUT_DIR/hardware/lspci.txt 2> /dev/null
	lspci -vv 1> $OUTPUT_DIR/hardware/lspci_vv.txt 2> /dev/null
	lspci -nn -k 1> $OUTPUT_DIR/hardware/lspci_nn_k.txt 2> /dev/null
	lshal 1> $OUTPUT_DIR/hardware/lshal.txt 2> /dev/null
	lsscsi 1> $OUTPUT_DIR/hardware/lsscsi.txt 2> /dev/null
	lsusb 1> $OUTPUT_DIR/hardware/lsusb.txt 2> /dev/null
	lsusb -vv 1> $OUTPUT_DIR/hardware/lsusb_vv.txt 2> /dev/null
	pciconf -l 1> $OUTPUT_DIR/hardware/pciconf.txt 2> /dev/null
	pciconf -l -v 1> $OUTPUT_DIR/hardware/pciconf_l_v.txt 2> /dev/null
	pcidump -v 1> $OUTPUT_DIR/hardware/pcidump.txt 2> /dev/null
	usbconfig show_ifdrv 1> $OUTPUT_DIR/hardware/usbconfig_show_ifdrv.txt 2> /dev/null
	usbdevs -v 1> $OUTPUT_DIR/hardware/usbdevs_v.txt 2> /dev/null
	lshw -businfo 1> $OUTPUT_DIR/hardware/lshw_businfo.txt 2> /dev/null
	lspci -vvknnqq 1> $OUTPUT_DIR/hardware/lspci_vvknnqq.txt 2> /dev/null
fi


# ------------------------------------
# PART 4: INSTALLED SOFTWARE / PATCHES
# ------------------------------------

echo "${COL_SECTION}INSTALLED SOFTWARE AND PATCHES [25% ]:${RESET}"
mkdir $OUTPUT_DIR/software

echo "  ${COL_ENTRY}>${RESET} Installed software (this could take a few mins)"
if [ $PLATFORM = "solaris" ]
then
    pkginfo -l 1> $OUTPUT_DIR/software/software-pkginfo-l.txt 2> /dev/null
    pkginfo -x 1> $OUTPUT_DIR/software/software-pkginfo-x.txt 2> /dev/null
    showrev 1> $OUTPUT_DIR/software/software-showrev.txt 2> /dev/null
    pkginfo -x 2> /dev/null | awk '{ if ( NR % 2 ) { prev = $1 } else { print prev" "$0 } }' > $OUTPUT_DIR/software/solaris-pkginfo.txt 2> /dev/null
    showrev -a > $OUTPUT_DIR/software/showrev.txt 2> /dev/null
elif [ $PLATFORM = "aix" ]
then
    lslpp -L all 1> $OUTPUT_DIR/software/software-lslpp.txt 2> /dev/null
    lslpp -Lc 1> $OUTPUT_DIR/software/aix-patchlist.txt 2> /dev/null
    pkginfo 1> $OUTPUT_DIR/software/software-pkginfo.txt 2> /dev/null
elif [ $PLATFORM = "android" ]
then
    find / -iname "*.apk" 1> $OUTPUT_DIR/software/software-apps.txt 2> /dev/null
	pm list packages 1> $OUTPUT_DIR/software/list_packages-pm.txt 2> /dev/null 
	cmd package list packages -f -u -i -U 1> $OUTPUT_DIR/software/android_list_packages-package.txt 2> /dev/null 
	dumpsys -l 1> $OUTPUT_DIR/software/android_services_list.txt 2> /dev/null
	dumpsys 1> $OUTPUT_DIR/software/android_services_dumpsys.txt 2> /dev/null
	pm list libraries 1> $OUTPUT_DIR/software/android_libraries.txt 2> /dev/null
	pm list permissions -f -u 1> $OUTPUT_DIR/software/android_permissions.txt 2> /dev/null
	pm list permission-groups -f 1> $OUTPUT_DIR/software/android_group_permissions.txt 2> /dev/null
	pm list instrumentation 1> $OUTPUT_DIR/software/android_instrumentation.txt 2> /dev/null
	pm list features 1> $OUTPUT_DIR/software/android_features.txt 2> /dev/null
	pm get-install-location 1> $OUTPUT_DIR/software/android_install_location.txt 2> /dev/null
elif [ $PLATFORM = "mac" ]
then
    find / -iname "*.app" 1> $OUTPUT_DIR/software/software-apps.txt 2> /dev/null
	find / -iname "*.plist" 1> $OUTPUT_DIR/software/software-plist.txt 2> /dev/null
    ls -la /Applications/ 1> $OUTPUT_DIR/software/software-Applications-folder.txt 2> /dev/null
	mkdir $OUTPUT_DIR/software/System_Kernel_Extensions/ 2> /dev/null
	cp -R /System/Library/Extensions/ $OUTPUT_DIR/software/System_Kernel_Extensions/ 2> /dev/null
	mkdir $OUTPUT_DIR/software/Library_Kernel_Extensions/ 2> /dev/null
	cp -R /Library/Extensions/ $OUTPUT_DIR/software/Library_Kernel_Extensions/ 2> /dev/null
elif [ $PLATFORM = "hpux" ]
then
    swlist 1> $OUTPUT_DIR/software/software-swlist.txt 2> /dev/null
    swlist -l fileset -a revision 1> $OUTPUT_DIR/software/hpux-patchlist.txt 2> /dev/null
else
    cp /etc/redhat-release $OUTPUT_DIR/software/ 2> /dev/null
    rpm -q -a 1> $OUTPUT_DIR/software/software-rpm.txt 2> /dev/null
    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n' > $OUTPUT_DIR/software/rpm-patchlist.txt 2> /dev/null
    dpkg --list 1> $OUTPUT_DIR/software/software-dpkg.txt 2> /dev/null
    dpkg -l 1> $OUTPUT_DIR/software/dpkg-patchlist.txt 2> /dev/null
    ls -1 /var/log/packages 1> $OUTPUT_DIR/software/slackware-patchlist.txt 2> /dev/null
    grep -A 1 displayName /Library/Receipts/InstallHistory.plist 2>/dev/null| grep string | sed 's/<string>\(.*\)<\/string>.*/\1/g'  | sed 's/^[      ]*//g'|tr  -d -c 'a-zA-Z0-9\n _-'|sort|uniq > $OUTPUT_DIR/software/osx-patchlist.txt 2> /dev/null
    ls -1 /Library/Receipts/boms /private/var/db/receipts 2>/dev/null | grep '\.bom$' > $OUTPUT_DIR/software/osx-bomlist.txt 2> /dev/null
    emerge -pev world 1> $OUTPUT_DIR/software/software-emerge.txt 2> /dev/null
    pkg_info > $OUTPUT_DIR/software/freebsd-patchlist.txt 2> /dev/null
    chkconfig --list $OUTPUT_DIR/software/chkconfig--list.txt 2> /dev/null
	pkg info > $OUTPUT_DIR/software/freebsd-patchlist_pkg_info.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Installed patches"
if [ $PLATFORM = "solaris" ]
then
    showrev -p 1> $OUTPUT_DIR/software/patches-showrev-p.txt 2> /dev/null
    patchadd -p 1> $OUTPUT_DIR/software/patches-patchadd-p.txt 2> /dev/null
elif [ $PLATFORM = "mac" ]
then
	system_profiler SPInstallHistoryDataType 1> $OUTPUT_DIR/software/patches-SPInstallHistoryDataType.txt 2> /dev/null
	softwareupdate --history --all 1> $OUTPUT_DIR/software/patches-history.txt 2> /dev/null
	cp /Library/Receipts/InstallHistory.plist $OUTPUT_DIR/software/ 2> /dev/null
elif [ $PLATFORM = "aix" ]
then
    instfix -a 1> $OUTPUT_DIR/software/patches-instfix.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Compiler tools (NFS skip)"
find / -fstype nfs -prune -o \( -name 'gcc*' -o -name 'javac*' -o -name 'java*' -o -name 'perl*' -o -name 'tclsh*' -o -name 'python*' -o -name 'ruby*' \) -ls 1> $OUTPUT_DIR/software/compiler.txt 2> /dev/null

# ------------------------------------
# PART 5: LOG FILES, HOME DIR and PROC folders
# ------------------------------------

echo "${COL_SECTION}LOG, HOME and PROC FILE COLLECTION [50% ]:${RESET}"
mkdir $OUTPUT_DIR/logs 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Copying logs"
if [ $PLATFORM = "solaris" ]
then
    cp -R /var/adm/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/log/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nslog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nsproflog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nssynclog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/share/adm/lastlog $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/share/adm/wtmpx $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /system/volatile/utmpx $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/svc/log $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/webui/logs $OUTPUT_DIR/logs/ 2> /dev/null
elif [ $PLATFORM = "aix" ]
then
    cp -R /var/adm/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/log/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nslog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nsproflog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nssynclog/ $OUTPUT_DIR/logs/ 2> /dev/null
	fcstkrpt -a 1> $OUTPUT_DIR/general/fast-fail-log.txt 2> /dev/null
	errpt -a 1> $OUTPUT_DIR/general/crash-log.txt 2> /dev/null
elif [ $PLATFORM = "android" ]
then
    logcat -d 1> $OUTPUT_DIR/logs/logcat-d.txt 2> /dev/null
	logcat -d *:D 1> $OUTPUT_DIR/logs/logcat-d-D.txt 2> /dev/null
	logcat -d *:I 1> $OUTPUT_DIR/logs/logcat-d-I.txt 2> /dev/null
	logcat -d *:W 1> $OUTPUT_DIR/logs/logcat-d-W.txt 2> /dev/null
	logcat -d *:E 1> $OUTPUT_DIR/logs/logcat-d-E.txt 2> /dev/null
	logcat -d *:F 1> $OUTPUT_DIR/logs/logcat-d-F.txt 2> /dev/null
elif [ $PLATFORM = "mac" ]
then
	mkdir $OUTPUT_DIR/logs/private_var_log
    cp -R /private/var/log $OUTPUT_DIR/logs/private_var_log/ 2> /dev/null
	mkdir $OUTPUT_DIR/logs/private_var_logs
	cp -R /private/var/logs $OUTPUT_DIR/logs/private_var_logs/ 2> /dev/null
	mkdir $OUTPUT_DIR/logs/var_log
	cp -R /var/log $OUTPUT_DIR/logs/var_log/ 2> /dev/null
	mkdir $OUTPUT_DIR/logs/library_logs
	cp -R /Library/Logs $OUTPUT_DIR/logs/library_logs/ 2> /dev/null
elif [ $PLATFORM = "linux" ]
then
    cp -R /var/log/ $OUTPUT_DIR/logs/ 2> /dev/null
    cp -R /var/adm/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nslog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nsproflog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nssynclog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/run/log $OUTPUT_DIR/logs/ 2> /dev/null
elif [ $PLATFORM = "generic" ]
then
    cp -R /var/log/ $OUTPUT_DIR/logs/ 2> /dev/null
    cp -R /var/adm/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nslog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nsproflog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nssynclog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/run/log $OUTPUT_DIR/logs/ 2> /dev/null
elif [ $PLATFORM = "hpux" ]
then
    cp -R /var/log/ $OUTPUT_DIR/logs/ 2> /dev/null
    cp -R /var/adm/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nslog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nsproflog/ $OUTPUT_DIR/logs/ 2> /dev/null
	cp -R /var/nssynclog/ $OUTPUT_DIR/logs/ 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Copying home dirs"
mkdir $OUTPUT_DIR/homedir
if [ $PLATFORM = "solaris" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/home-export 1> /dev/null 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /home/ $OUTPUT_DIR/homedir/home/ 1> /dev/null 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /root/ $OUTPUT_DIR/homedir/root/ 1> /dev/null 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /export/home/ $OUTPUT_DIR/homedir/home-export/ 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/home-export 1> /dev/null 2> /dev/null
		find /home/ /export/home/ /root/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/homedir/oversized_files.txt
		tar --exclude=$OUTPUT_DIR -cvfX $OUTPUT_DIR/homedir/home/home.tar $OUTPUT_DIR/homedir/oversized_files.txt /home/ 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvfX $OUTPUT_DIR/homedir/root/root.tar $OUTPUT_DIR/homedir/oversized_files.txt /root/ 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvfX $OUTPUT_DIR/homedir/home-export/home-export.tar $OUTPUT_DIR/homedir/oversized_files.txt /export/home/ 1> /dev/null 2> /dev/null
	fi
elif [ $PLATFORM = "aix" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /home/ $OUTPUT_DIR/homedir/home/ 1> /dev/null 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /root/ $OUTPUT_DIR/homedir/root/ 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 2> /dev/null
		find /home/ /root/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/homedir/oversized_files.txt
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/homedir/home/home.tar /home/ --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/homedir/root/root.tar /root/ --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null
	fi 
elif [ $PLATFORM = "mac" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/homedir/Users 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /Users/ $OUTPUT_DIR/homedir/Users/ 1> /dev/null 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /home/ $OUTPUT_DIR/homedir/home/ 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		mkdir $OUTPUT_DIR/homedir/Users 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		find /Users/ /home/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/homedir/oversized_files.txt
		tar --exclude=$OUTPUT_DIR --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt -cvf $OUTPUT_DIR/homedir/home/Users.tar /Users/  1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt -cvf $OUTPUT_DIR/homedir/home/home.tar /home/  1> /dev/null 2> /dev/null
	fi 	
elif [ $PLATFORM = "linux" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /home/ $OUTPUT_DIR/homedir/home/ 1> /dev/null 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /root/ $OUTPUT_DIR/homedir/root/ 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 2> /dev/null
		find /root/ /home/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/homedir/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/homedir/home/home.tar /home/ --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null || tar -cvf $OUTPUT_DIR/homedir/home/home.tar /home/  --exclude=$OUTPUT_DIR --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/homedir/root/root.tar /root/ --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null || tar -cvf $OUTPUT_DIR/homedir/root/root.tar /root/ --exclude=$OUTPUT_DIR --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null 
	fi 
elif [ $PLATFORM = "generic" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /home/ $OUTPUT_DIR/homedir/home/ 1> /dev/null 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /root/ $OUTPUT_DIR/homedir/root/ 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 2> /dev/null
		find /home/ /root/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/homedir/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/homedir/home/home.tar /home/ --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null || tar -cvf $OUTPUT_DIR/homedir/home/home.tar /home/  --exclude=$OUTPUT_DIR --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/homedir/root/root.tar /root/ --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null || tar -cvf $OUTPUT_DIR/homedir/root/root.tar /root/ --exclude=$OUTPUT_DIR --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null 
	fi 
elif [ $PLATFORM = "hpux" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /home/ $OUTPUT_DIR/homedir/home/ 1> /dev/null 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude $OUTPUT_DIR /root/ $OUTPUT_DIR/homedir/root/ 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		mkdir $OUTPUT_DIR/homedir/home 2> /dev/null
		mkdir $OUTPUT_DIR/homedir/root 2> /dev/null
		find /home/ /root/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/homedir/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/homedir/home/home.tar /home/ --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null || tar -cvf $OUTPUT_DIR/homedir/home/home.tar /home/  --exclude=$OUTPUT_DIR --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/homedir/root/root.tar /root/ --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null || tar -cvf $OUTPUT_DIR/homedir/root/root.tar /root/ --exclude=$OUTPUT_DIR --exclude-from $OUTPUT_DIR/homedir/oversized_files.txt 1> /dev/null 2> /dev/null 
	fi 
fi

mkdir $OUTPUT_DIR/procfiles 2> /dev/null
echo "  ${COL_ENTRY}>${RESET} Copying proc dirs"
# No /proc on mac and hpux
if [ $PLATFORM = "solaris" ]
then
    find /proc/ -type f \( -name "cmdline" -o -name "psinfo" -o -name "fib_triestat" -o -name "status" -o -name "connector" -o -name "protocols" -o -name "route" -o -name "fib_trie" -o -name "snmp*" \) 2>/dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
elif [ $PLATFORM = "aix" ]
then
    find /proc/ -type f \( -name "cred" -o -name "psinfo" -o -name "mmap" -o -name "cwd" -o -name "fd" -o -name "sysent" \) 2>/dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
elif [ $PLATFORM = "linux" ]
then
    find /proc/ -type f \( -name "cmdline" -o -name "fib_triestat" -o -name "status" -o -name "connector" -o -name "protocols" -o -name "route" -o -name "fib_trie" -o -name "snmp*" \) 2>/dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
elif [ $PLATFORM = "android" ]
then
    find /proc/ -type f \( -name 'cmdline' -o -name 'fib_triestat' -o -name 'status' -o -name 'connector' -o -name 'route' -o -name 'fib_trie' \) 2>/dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
elif [ $PLATFORM = "generic" ]
then
    find /proc/ -type f \( -name "cmdline" -o -name "fib_triestat" -o -name "status" -o -name "connector" -o -name "protocols" -o -name "route" -o -name "fib_trie" -o -name "snmp*" \) 2>/dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
fi

mkdir $OUTPUT_DIR/tmpfiles 2> /dev/null
echo "  ${COL_ENTRY}>${RESET} Copying /tmp/ and /var/tmp/ dirs where possible"

if [ $PLATFORM = "solaris" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/tmpfiles/tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /tmp/ $OUTPUT_DIR/tmpfiles/tmp 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/tmpfiles/var_tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /var/tmp/ $OUTPUT_DIR/tmpfiles/var_tmp 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		find /tmp/ /var/tmp/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/tmpfiles/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvfX $OUTPUT_DIR/tmpfiles/tmp.tar $OUTPUT_DIR/tmpfiles/oversized_files.txt /tmp/ 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvfX $OUTPUT_DIR/tmpfiles/var_tmp.tar $OUTPUT_DIR/tmpfiles/oversized_files.txt /var/tmp/ 1> /dev/null 2> /dev/null
	fi 
elif [ $PLATFORM = "aix" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/tmpfiles/tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /tmp/ $OUTPUT_DIR/tmpfiles/tmp 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/tmpfiles/var_tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /var/tmp/ $OUTPUT_DIR/tmpfiles/var_tmp 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		find /tmp/ /var/tmp/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/tmpfiles/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/tmp.tar /tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/var_tmp.tar /var/tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
	fi 
elif [ $PLATFORM = "linux" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/tmpfiles/tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /tmp/ $OUTPUT_DIR/tmpfiles/tmp 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/tmpfiles/var_tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /var/tmp/ $OUTPUT_DIR/tmpfiles/var_tmp 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		find /tmp/ /var/tmp/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/tmpfiles/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/tmp.tar /tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/var_tmp.tar /var/tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
	fi 
elif [ $PLATFORM = "mac" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/tmpfiles/tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /tmp/ $OUTPUT_DIR/tmpfiles/tmp 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/tmpfiles/private_tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /private/tmp/ $OUTPUT_DIR/tmpfiles/private_tmp 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/tmpfiles/var_tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /var/tmp/ $OUTPUT_DIR/tmpfiles/var_tmp 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
	    find /tmp/ /private/tmp/ /var/tmp/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/tmpfiles/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/tmp.tar /tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/private_tmp.tar /private/tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/var_tmp.tar /var/tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
	fi 
elif [ $PLATFORM = "generic" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/tmpfiles/tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /tmp/ $OUTPUT_DIR/tmpfiles/tmp 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/tmpfiles/var_tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /var/tmp/ $OUTPUT_DIR/tmpfiles/var_tmp 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		find /tmp/ /var/tmp/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/tmpfiles/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/tmp.tar /tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/var_tmp.tar /var/tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
	fi 
elif [ $PLATFORM = "hpux" ]
then
	if [ -x "$(command -v rsync)" ]
	then
		mkdir $OUTPUT_DIR/tmpfiles/tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /tmp/ $OUTPUT_DIR/tmpfiles/tmp 1> /dev/null 2> /dev/null
		mkdir $OUTPUT_DIR/tmpfiles/var_tmp 2> /dev/null
		rsync -av --max-size=$RSYNC_MAX_FILESIZE --exclude '*.vmdk' --exclude '*.ovf' --exclude '*.ova' --exclude '*.vhd' --exclude '*.vmss' --exclude=$OUTPUT_DIR /var/tmp/ $OUTPUT_DIR/tmpfiles/var_tmp 1> /dev/null 2> /dev/null
	elif [ -x "$(command -v tar)" ]
	then
		find /tmp/ /var/tmp/ -size $TAR_MAX_FILESIZE >> $OUTPUT_DIR/tmpfiles/oversized_files.txt 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/tmp.tar /tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
		tar --exclude=$OUTPUT_DIR -cvf $OUTPUT_DIR/tmpfiles/var_tmp.tar /var/tmp/ --exclude-from $OUTPUT_DIR/tmpfiles/oversized_files.txt 1> /dev/null 2> /dev/null
	fi 
fi


if [ $PLATFORM = "mac" ]
then
	echo "${COL_SECTION} Searching plist files [55% ]: ${RESET}"
	mkdir $OUTPUT_DIR/plist
	find / -size $TAR_MAX_FILESIZE -type f -iname "*.plist" 2>/dev/null | while read line
	do  
	    FILENAME=$(printf %q "$line")
		echo $FILENAME >> $OUTPUT_DIR/plist/plist.files.txt
	done
	echo "  ${COL_ENTRY}>${RESET} Copying all plist files"
	while read pListFiles; do
	    mkdir -p "$OUTPUT_DIR/plist$(dirname "$pListFiles")" 2> /dev/null
		cp -p "$pListFiles" "$OUTPUT_DIR/plist$(dirname "$pListFiles")" 2> /dev/null
	done <$OUTPUT_DIR/plist/plist.files.txt

elif [ $PLATFORM = "android" ]
then
	echo "${COL_SECTION} Searching for APK files [55% ]: ${RESET}" 
	mkdir $OUTPUT_DIR/apk
	find / -size $TAR_MAX_FILESIZE -type f -iname "*.apk" 2>/dev/null | while read line
	do
	    FILENAME=$(printf %q "$line")
		echo $FILENAME >> $OUTPUT_DIR/apk/apk.files.txt
	done
	echo "  ${COL_ENTRY}>${RESET} Copying all apk files"
	while read apkFiles; do
	    mkdir -p "$OUTPUT_DIR/apk$(dirname "$apkFiles")" 2> /dev/null
		cp -p "$apkFiles" "$OUTPUT_DIR/apk$(dirname "$apkFiles")" 2> /dev/null
	done <$OUTPUT_DIR/apk/apk.files.txt
fi

# ------------------------------------
# PART 6: SUID
# ------------------------------------

echo "${COL_SECTION}SUID/SGID SEARCH [60% ]:${RESET}"
mkdir $OUTPUT_DIR/setuid
if [ $PLATFORM = "android" ]
then
	echo "  ${COL_ENTRY}>${RESET} Finding all SUID/SGID binaries"
	find / -type f -a -perm /6000 2>/dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/setuid`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/setuid`dirname $line`" 2> /dev/null
	done
else
	echo "  ${COL_ENTRY}>${RESET} Finding all SUID/SGID binaries"
	find / -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/setuid`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/setuid`dirname $line`" 2> /dev/null
	done
fi


# ------------------------------------
# PART 7: BINARY HASHES
# ------------------------------------

echo "${COL_SECTION}HASH BINARIES [65% ]:${RESET}"
echo "  ${COL_ENTRY}>${RESET} Hashing all SUID/SGID binaries"
mkdir $OUTPUT_DIR/hashes
if [ $PLATFORM = "linux" ]
then 
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "solaris" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec digest -a sha256 -v {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec csum -h MD5 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi	
elif [ $PLATFORM = "mac" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec shasum -a 256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "android" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec shasum -a 256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi		
fi

echo "  ${COL_ENTRY}>${RESET} Hashing all HOME dirs"
if [ $PLATFORM = "linux" ]
then 
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "solaris" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec digest -a sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec csum -h MD5 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi	
elif [ $PLATFORM = "mac" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec shasum -a 256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi	
fi

if [ $PLATFORM = "linux" ]
then 
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done
    fi		
elif [ $PLATFORM = "solaris" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec digest -a sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec csum -h MD5 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/shaMD5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "mac" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec shasum -a 256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi	
elif [ $PLATFORM = "android" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /storage/ /system/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec shasum -a 256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
fi

# ---------------------------
# PART 8: NETWORK INFORMATION
# ---------------------------

echo "${COL_SECTION}NETWORK INFORMATION [90% ]:${RESET}"
mkdir $OUTPUT_DIR/network

echo "  ${COL_ENTRY}>${RESET} Interface configuration"
if [ $PLATFORM = "hpux" ]
then
    lanscan -v 1> $OUTPUT_DIR/network/network-devices.txt 2> /dev/null
    for lanif in 0 1 2 3 4 5 6 7 8 9 10 11 12
    do
        ifconfig lan$lanif 1>> $OUTPUT_DIR/network/network-ip.txt 2> /dev/null
    done
elif [ $PLATFORM = "aix" ]
then
    lsdev -Cc if 1> $OUTPUT_DIR/network/network-devices.txt 2> /dev/null
    ifconfig -a 1> $OUTPUT_DIR/network/ifconfig-a.txt 2> /dev/null
else
    ifconfig -a 1> $OUTPUT_DIR/network/ifconfig-a.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} IP addr"
ip addr 1> $OUTPUT_DIR/network/ipaddr.txt 2> /dev/null
ip netconf 1> $OUTPUT_DIR/network/ipnetconf.txt 2> /dev/null
ifconfig -a 1> $OUTPUT_DIR/network/ifconfig-a.txt 2> /dev/null
plutil -p /Library/Preferences/SystemConfiguration/preferences.plist 1> $OUTPUT_DIR/network/network_preferences_mac.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} IP forwarding"
if [ $PLATFORM = "aix" ]
then
    no -o ipforwarding 1> $OUTPUT_DIR/network/ipforwarding.txt 2> /dev/null
elif [ $PLATFORM = "linux" ]
then
    cat -s /proc/sys/net/ipv4/ip_forward 1> $OUTPUT_DIR/network/ipforwarding.txt 2> /dev/null
elif [ $PLATFORM = "hpux" -o $PLATFORM = "solaris" ]
then
    ndd -get /dev/ip ip_forwarding 1> $OUTPUT_DIR/network/ipforwarding.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Routing"
netstat -anr 1> $OUTPUT_DIR/network/route.txt 2> /dev/null
ip route 1> $OUTPUT_DIR/network/ip_route.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Netstat"
netstat -an 1> $OUTPUT_DIR/network/netstat-an.txt 2> /dev/null
ss -an 1> $OUTPUT_DIR/network/ss-an.txt 2> /dev/null

if [ $PLATFORM != "solaris" ]
then
	netstat -anp 1> $OUTPUT_DIR/network/netstat-apn.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} ARP cache"
arp -a 1> $OUTPUT_DIR/network/arp.txt 2> /dev/null
ip neighbour 1> $OUTPUT_DIR/network/ip_neighbour.txt 2> /dev/null

if [ -f /etc/ethers ]
then
    echo "  ${COL_ENTRY}>${RESET} Ethers"
    cat -s /etc/ethers 1> $OUTPUT_DIR/network/ethers.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Hosts"
cat -s /etc/hosts 1> $OUTPUT_DIR/network/hosts.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} DNS"
cat -s /etc/resolv.conf 1> $OUTPUT_DIR/network/dns.txt 2> /dev/null

if [ -f /etc/hosts.allow -o -f /etc/hosts.deny ]
then
    echo "  ${COL_ENTRY}>${RESET} TCP wrappers"
    cat -s /etc/hosts.allow 1> $OUTPUT_DIR/network/hosts.allow 2> /dev/null
    cat -s /etc/hosts.deny 1> $OUTPUT_DIR/network/hosts.deny 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} RPC"
rpcinfo -p 1> $OUTPUT_DIR/network/rpcinfo.txt 2> /dev/null

if [ -x /sbin/iptables -o -x /system/bin/iptables ]
then
    echo "  ${COL_ENTRY}>${RESET} IP Tables"
    iptables -L -v -n 1> $OUTPUT_DIR/network/iptables.txt 2> /dev/null
fi

if [ -x /sbin/ip6tables -o -x /system/bin/ip6tables ]
then
    echo "  ${COL_ENTRY}>${RESET} IP Tables (IPv6)"
    ip6tables -L -v -n 1> $OUTPUT_DIR/network/ip6tables.txt 2> /dev/null
fi

if [ -f /etc/ipf/ipf.conf -o -f /etc/opt/ipf/ipf.conf ]
then
    echo "  ${COL_ENTRY}>${RESET} IP Filter"
    cat -s /etc/ipf/ipf.conf 1> $OUTPUT_DIR/network/ipf.conf 2> /dev/null
    cat -s /etc/opt/ipf/ipf.conf 1> $OUTPUT_DIR/network/ipf.conf 2> /dev/null
fi


# ---------------------------
# PART 9: VIRTUAL SYSTEMS INFORMATION
# ---------------------------
if [ -x "$(command -v esxcli)" -o -x "$(command -v VBoxManage)" -o -x "$(command -v virsh)" -o -x "$(command -v vim-cmd)" -o -x "$(command -v vmctl)" -o -x "$(command -v qm)" ]
then
    echo "${COL_SECTION}VIRTUAL SYSTEMS INFORMATION [95% ]:${RESET}"
    mkdir $OUTPUT_DIR/virtual
	# VMWARE
	if [ -x "$(command -v esxcli)" -o -x "$(command -v vm-support)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting VMware ESXi information"
		esxcli system version get 1> $OUTPUT_DIR/virtual/esxi_version.txt 2> /dev/null
		esxcli system hostname get 1> $OUTPUT_DIR/virtual/esxi_hostname.txt 2> /dev/null
		esxcli system stats installtime get 1> $OUTPUT_DIR/virtual/esxi_installtime.txt 2> /dev/null
		esxcli system account list 1> $OUTPUT_DIR/virtual/esxi_account_list.txt 2> /dev/null
		esxcli network firewall get 1> $OUTPUT_DIR/virtual/esxi_firewall_status.txt 2> /dev/null
		esxcli software vib list 1> $OUTPUT_DIR/virtual/esxi_software_vib_list.txt 2> /dev/null
		esxcli network firewall ruleset list 1> $OUTPUT_DIR/virtual/esxi_firewall_ruleset.txt 2> /dev/null
		esxcli network ip interface ipv4 get 1> $OUTPUT_DIR/virtual/esxi_ip4.txt 2> /dev/null
		esxcli network vm list 1> $OUTPUT_DIR/virtual/esxi_vm_network_vm_list.txt 2> /dev/null
		esxcli vm process list 1> $OUTPUT_DIR/virtual/esxi_vm_process_list.txt 2> /dev/null
		esxcli storage vmfs extent list 1> $OUTPUT_DIR/virtual/esxi_vmfs_list.txt 2> /dev/null
		esxcli storage filesystem list 1> $OUTPUT_DIR/virtual/esxi_volumes_list.txt 2> /dev/null
		esxcli network ip connection list 1> $OUTPUT_DIR/virtual/esxi_network_connection_list.txt 2> /dev/null
		esxcli hardware cpu list 1> $OUTPUT_DIR/virtual/esxi_hardware_cpu_list.txt 2> /dev/null
		esxcli hardware usb passthrough device list 1> $OUTPUT_DIR/virtual/esxi_hardware_usb_passthrough_list.txt 2> /dev/null
		esxcli hardware bootdevice list 1> $OUTPUT_DIR/virtual/esxi_hardware_bootdevice_list.txt 2> /dev/null
		esxcli hardware clock get 1> $OUTPUT_DIR/virtual/esxi_hardware_clock_list.txt 2> /dev/null
		esxcli hardware memory get 1> $OUTPUT_DIR/virtual/esxi_hardware_memory_list.txt 2> /dev/null
		esxcli hardware pci list 1> $OUTPUT_DIR/virtual/esxi_hardware_pci_list.txt 2> /dev/null
		esxcli hardware platform get 1> $OUTPUT_DIR/virtual/esxi_hardware_platform_details.txt 2> /dev/null
		esxcli hardware trustedboot get 1> $OUTPUT_DIR/virtual/esxi_hardware_trustedboot_details.txt 2> /dev/null
		vmware -vl 1> $OUTPUT_DIR/virtual/esxi_version2.txt 2> /dev/null
		vmkchdev -l 1> $OUTPUT_DIR/virtual/esxi_devices.txt 2> /dev/null
		esxcli system process list 1> $OUTPUT_DIR/virtual/esxi_system_process_list.txt 2> /dev/null
		vm-support -V 1> $OUTPUT_DIR/virtual/esxi_vm_support.txt 2> /dev/null
		esxcli storage nfs list 1> $OUTPUT_DIR/virtual/esxi_nfs_storage_list.txt 2> /dev/null
		esxcli storage nfs41 list 1> $OUTPUT_DIR/virtual/esxi_nfs4.1_storage_list.txt 2> /dev/null
		esxcli system settings advanced list 1> $OUTPUT_DIR/virtual/esxi_advanced_settings.txt 2> /dev/null
		esxcli system settings kernel list 1> $OUTPUT_DIR/virtual/esxi_kernel_settings.txt 2> /dev/null
		esxcli system module list 1> $OUTPUT_DIR/virtual/esxi_kernel_modules.txt 2> /dev/null
		esxcli system module get -m vmkernel 1> $OUTPUT_DIR/virtual/esxi_vmkernel_info.txt 2> /dev/null
		esxcli system security certificatestore list 1> $OUTPUT_DIR/virtual/esxi_certificates.txt 2> /dev/null
		esxcli software acceptance get 1> $OUTPUT_DIR/virtual/esxi_software_acceptance.txt 2> /dev/null
		esxcli system maintenanceMode get 1> $OUTPUT_DIR/virtual/esxi_maintenance_mode.txt 2> /dev/null
		esxcli hardware power policy list 1> $OUTPUT_DIR/virtual/esxi_power_policy.txt 2> /dev/null
		esxcli hardware power policy get 1> $OUTPUT_DIR/virtual/esxi_current_power_policy.txt 2> /dev/null
		esxcli system time get 1> $OUTPUT_DIR/virtual/esxi_time_config.txt 2> /dev/null
		esxcli system ntp get 1> $OUTPUT_DIR/virtual/esxi_ntp_config.txt 2> /dev/null
		esxcli system syslog config get 1> $OUTPUT_DIR/virtual/esxi_syslog_config.txt 2> /dev/null
		esxcli system syslog config logger list 1> $OUTPUT_DIR/virtual/esxi_syslog_loggers.txt 2> /dev/null
		esxcli network vswitch standard list 1> $OUTPUT_DIR/virtual/esxi_vswitch_standard_list.txt 2> /dev/null
		esxcli network vswitch dvs vmware list 1> $OUTPUT_DIR/virtual/esxi_vswitch_dvs_list.txt 2> /dev/null
		esxcli network vswitch standard portgroup list 1> $OUTPUT_DIR/virtual/esxi_portgroup_list.txt 2> /dev/null
		for vswitch in $(esxcli network vswitch standard list 2>/dev/null | grep "^   " | awk '{print $1}'); do
			echo "=== vSwitch: $vswitch ===" >> $OUTPUT_DIR/virtual/esxi_vswitch_policies.txt
			esxcli network vswitch standard policy security get -v "$vswitch" >> $OUTPUT_DIR/virtual/esxi_vswitch_policies.txt 2> /dev/null
			esxcli network vswitch standard policy failover get -v "$vswitch" >> $OUTPUT_DIR/virtual/esxi_vswitch_policies.txt 2> /dev/null
			esxcli network vswitch standard policy shaping get -v "$vswitch" >> $OUTPUT_DIR/virtual/esxi_vswitch_policies.txt 2> /dev/null
			echo "" >> $OUTPUT_DIR/virtual/esxi_vswitch_policies.txt
		done
		esxcli network nic list 1> $OUTPUT_DIR/virtual/esxi_network_nic_list.txt 2> /dev/null
		esxcli network ip interface list 1> $OUTPUT_DIR/virtual/esxi_ip_interface_list.txt 2> /dev/null
		esxcli network ip interface ipv6 get 1> $OUTPUT_DIR/virtual/esxi_ipv6.txt 2> /dev/null
		esxcli storage core adapter list 1> $OUTPUT_DIR/virtual/esxi_storage_adapters.txt 2> /dev/null
		esxcli storage core device list 1> $OUTPUT_DIR/virtual/esxi_storage_devices.txt 2> /dev/null
		esxcli storage core path list 1> $OUTPUT_DIR/virtual/esxi_storage_paths.txt 2> /dev/null
		esxcli storage core plugin list 1> $OUTPUT_DIR/virtual/esxi_storage_plugins.txt 2> /dev/null
		esxcli iscsi adapter list 1> $OUTPUT_DIR/virtual/esxi_iscsi_adapters.txt 2> /dev/null
		esxcli iscsi session list 1> $OUTPUT_DIR/virtual/esxi_iscsi_sessions.txt 2> /dev/null
		esxcli iscsi ibftboot get 1> $OUTPUT_DIR/virtual/esxi_iscsi_boot.txt 2> /dev/null
		esxcli vsan cluster get 1> $OUTPUT_DIR/virtual/esxi_vsan_cluster.txt 2> /dev/null
		esxcli vsan network list 1> $OUTPUT_DIR/virtual/esxi_vsan_network.txt 2> /dev/null
		esxcli vsan storage list 1> $OUTPUT_DIR/virtual/esxi_vsan_storage.txt 2> /dev/null
		esxcli vsan policy getdefault 1> $OUTPUT_DIR/virtual/esxi_vsan_policy.txt 2> /dev/null
		if [ -x "$(command -v vim-cmd)" ]; then
			echo "  ${COL_ENTRY}>${RESET} Collecting detailed VM information"
			vim-cmd vmsvc/getallvms 1> $OUTPUT_DIR/virtual/esxi_vim_all_vms.txt 2> /dev/null
			vim-cmd vmsvc/getallvms 2>/dev/null | awk 'NR>1 {print $1}' | while read vmid; do
				if [ -n "$vmid" ] && [ "$vmid" -eq "$vmid" ] 2>/dev/null; then
					echo "=== VM ID: $vmid ===" >> $OUTPUT_DIR/virtual/esxi_vm_details.txt
					vim-cmd vmsvc/get.summary $vmid >> $OUTPUT_DIR/virtual/esxi_vm_details.txt 2> /dev/null
					vim-cmd vmsvc/get.config $vmid >> $OUTPUT_DIR/virtual/esxi_vm_details.txt 2> /dev/null
					vim-cmd vmsvc/get.runtime $vmid >> $OUTPUT_DIR/virtual/esxi_vm_details.txt 2> /dev/null
					vim-cmd vmsvc/get.guest $vmid >> $OUTPUT_DIR/virtual/esxi_vm_details.txt 2> /dev/null
					vim-cmd vmsvc/get.datastores $vmid >> $OUTPUT_DIR/virtual/esxi_vm_details.txt 2> /dev/null
					vim-cmd vmsvc/get.networks $vmid >> $OUTPUT_DIR/virtual/esxi_vm_details.txt 2> /dev/null
					vim-cmd vmsvc/get.snapshot $vmid >> $OUTPUT_DIR/virtual/esxi_vm_details.txt 2> /dev/null
					vim-cmd vmsvc/device.getdevices $vmid >> $OUTPUT_DIR/virtual/esxi_vm_details.txt 2> /dev/null
					echo "" >> $OUTPUT_DIR/virtual/esxi_vm_details.txt
				fi
			done
			vim-cmd hostsvc/hosthardware > $OUTPUT_DIR/virtual/esxi_host_hardware.txt 2> /dev/null
			vim-cmd hostsvc/hostsummary > $OUTPUT_DIR/virtual/esxi_host_summary.txt 2> /dev/null
			vim-cmd hostsvc/datastore/listsummary > $OUTPUT_DIR/virtual/esxi_datastore_summary.txt 2> /dev/null
		fi
		
		esxtop -b -n 1 > $OUTPUT_DIR/virtual/esxi_esxtop_snapshot.txt 2> /dev/null
		vmkerrcode -l > $OUTPUT_DIR/virtual/esxi_error_codes.txt 2> /dev/null
		vmkload_mod -l > $OUTPUT_DIR/virtual/esxi_loaded_modules.txt 2> /dev/null
		vmkping -I vmk0 -c 1 localhost > $OUTPUT_DIR/virtual/esxi_vmkping_test.txt 2> /dev/null
		ls -la /var/log/ > $OUTPUT_DIR/virtual/esxi_log_listing.txt 2> /dev/null
		ls -la /scratch/log/ > $OUTPUT_DIR/virtual/esxi_scratch_log_listing.txt 2> /dev/null
		cp -R /scratch/log/ $OUTPUT_DIR/virtual/scratch_log/ 2> /dev/null
		cp -R /var/log/ $OUTPUT_DIR/virtual/esxi_var_log/
		vim-cmd vimsvc/license --show > $OUTPUT_DIR/virtual/esxi_license.txt 2> /dev/null
	fi
    #VBox
	if [ -x "$(command -v VBoxManage)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting VirtualBox information"
		VBoxManage list vms 1> $OUTPUT_DIR/virtual/vbox_vm_list.txt 2> /dev/null
		VBoxManage list runningvms 1> $OUTPUT_DIR/virtual/vbox_running_vm_list.txt 2> /dev/null
		VBoxManage list ostypes 1> $OUTPUT_DIR/virtual/vbox_ostypes_list.txt 2> /dev/null
		VBoxManage list hostinfo 1> $OUTPUT_DIR/virtual/vbox_hostinfo.txt 2> /dev/null
		VBoxManage list hddbackends 1> $OUTPUT_DIR/virtual/vbox_hddbackends.txt 2> /dev/null
		VBoxManage list systemproperties 1> $OUTPUT_DIR/virtual/vbox_systemproperties.txt 2> /dev/null
		VBoxManage list extpacks 1> $OUTPUT_DIR/virtual/vbox_extpacks.txt 2> /dev/null
		VBoxManage list groups 1> $OUTPUT_DIR/virtual/vbox_groups.txt 2> /dev/null
		VBoxManage list cloudproviders 1> $OUTPUT_DIR/virtual/vbox_cloudproviders.txt 2> /dev/null
		VBoxManage list cloudprofiles 1> $OUTPUT_DIR/virtual/vbox_cloudprofiles.txt 2> /dev/null
		VBoxManage list hostonlyifs 1> $OUTPUT_DIR/virtual/vbox_hostonly_interfaces.txt 2> /dev/null
		VBoxManage list natnets 1> $OUTPUT_DIR/virtual/vbox_nat_networks.txt 2> /dev/null
		VBoxManage list dhcpservers 1> $OUTPUT_DIR/virtual/vbox_dhcp_servers.txt 2> /dev/null
		VBoxManage list bridgedifs 1> $OUTPUT_DIR/virtual/vbox_bridged_interfaces.txt 2> /dev/null
		VBoxManage list intnets 1> $OUTPUT_DIR/virtual/vbox_internal_networks.txt 2> /dev/null
		VBoxManage list hostonlynets 1> $OUTPUT_DIR/virtual/vbox_hostonly_networks.txt 2> /dev/null
		VBoxManage list usbfilters 1> $OUTPUT_DIR/virtual/vbox_usb_filters.txt 2> /dev/null
		VBoxManage list usbhost 1> $OUTPUT_DIR/virtual/vbox_usb_host_devices.txt 2> /dev/null
		VBoxManage list hdds 1> $OUTPUT_DIR/virtual/vbox_hdds.txt 2> /dev/null
		VBoxManage list dvds 1> $OUTPUT_DIR/virtual/vbox_dvds.txt 2> /dev/null
		VBoxManage list floppies 1> $OUTPUT_DIR/virtual/vbox_floppies.txt 2> /dev/null
		VBoxManage list hostcpuids 1> $OUTPUT_DIR/virtual/vbox_host_cpuids.txt 2> /dev/null
		VBoxManage list hostdrives 1> $OUTPUT_DIR/virtual/vbox_host_drives.txt 2> /dev/null
		VBoxManage list hostdvds 1> $OUTPUT_DIR/virtual/vbox_host_dvds.txt 2> /dev/null
		VBoxManage list hostfloppies 1> $OUTPUT_DIR/virtual/vbox_host_floppies.txt 2> /dev/null
		VBoxManage list vms --long 1> $OUTPUT_DIR/virtual/vbox_vms_detailed.txt 2> /dev/null
		VBoxManage getextradata global enumerate 1> $OUTPUT_DIR/virtual/vbox_global_extradata.txt 2> /dev/null
		VBoxManage list vms | grep -E '^".*" \{' | sed 's/^"\(.*\)" {.*$/\1/' | while read vmname; do
			if [ -n "$vmname" ]; then
				echo "=== VM: $vmname ===" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt
				VBoxManage showvminfo "$vmname" --details >> $OUTPUT_DIR/virtual/vbox_vm_details.txt 2> /dev/null
				echo "--- Extra Data ---" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt
				VBoxManage getextradata "$vmname" enumerate >> $OUTPUT_DIR/virtual/vbox_vm_details.txt 2> /dev/null
				echo "--- Snapshots ---" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt
				VBoxManage snapshot "$vmname" list >> $OUTPUT_DIR/virtual/vbox_vm_details.txt 2> /dev/null
				echo "--- Storage ---" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt
				VBoxManage showvminfo "$vmname" --machinereadable | grep -E "storagecontroller|hdd|dvd|floppy" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt 2> /dev/null
				echo "--- Network ---" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt
				VBoxManage showvminfo "$vmname" --machinereadable | grep -E "nic[0-9]|macaddress|cableconnected|bridgeadapter" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt 2> /dev/null
				echo "--- USB ---" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt
				VBoxManage showvminfo "$vmname" --machinereadable | grep -E "usb|usbfilter" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/virtual/vbox_vm_details.txt
				VBoxManage showvminfo "$vmname" --machinereadable > "$OUTPUT_DIR/virtual/vbox_vm_${vmname//[^a-zA-Z0-9]/_}_machinereadable.txt" 2> /dev/null
			fi
		done
		VBoxManage metrics list > $OUTPUT_DIR/virtual/vbox_metrics_list.txt 2> /dev/null
		echo "  ${COL_ENTRY}>${RESET} Locating VirtualBox logs"
		VBOX_HOME=$(VBoxManage list systemproperties 2>/dev/null | grep "Default machine folder:" | sed 's/Default machine folder:[ ]*//')
		if [ -n "$VBOX_HOME" ] && [ -d "$VBOX_HOME" ]; then
			echo "VirtualBox Home: $VBOX_HOME" > $OUTPUT_DIR/virtual/vbox_log_locations.txt
			find "$VBOX_HOME" -name "*.log" -type f -mtime -7 2>/dev/null | head -100 >> $OUTPUT_DIR/virtual/vbox_log_locations.txt
		fi
		for homedir in /home/* /root; do
			if [ -d "$homedir/.VirtualBox" ]; then
				echo "Found VirtualBox config in: $homedir/.VirtualBox" >> $OUTPUT_DIR/virtual/vbox_config_locations.txt
				find "$homedir/.VirtualBox" -name "*.xml" -type f 2>/dev/null | head -50 >> $OUTPUT_DIR/virtual/vbox_config_locations.txt
			fi
			if [ -d "$homedir/VirtualBox VMs" ]; then
				echo "Found VirtualBox VMs in: $homedir/VirtualBox VMs" >> $OUTPUT_DIR/virtual/vbox_vm_locations.txt
				ls -la "$homedir/VirtualBox VMs/" >> $OUTPUT_DIR/virtual/vbox_vm_locations.txt 2> /dev/null
			fi
		done
		VBoxManage list vms --long 2>/dev/null | grep -A1 "Shared folders:" | grep -v "Shared folders:" | grep -v "^--$" > $OUTPUT_DIR/virtual/vbox_shared_folders.txt
		VBoxManage list extpacks | grep -i "guest" > $OUTPUT_DIR/virtual/vbox_guest_additions_info.txt 2> /dev/null
	fi
    # VIRT 
	if [ -x "$(command -v virsh)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting KVM/QEMU information"
		virsh list --all 1> $OUTPUT_DIR/virtual/virt_vm_list.txt 2> /dev/null
		virsh list --all --name 1> $OUTPUT_DIR/virtual/virt_vm_list_names.txt 2> /dev/null
		virsh hostname 1> $OUTPUT_DIR/virtual/virt_hostname.txt 2> /dev/null
		virsh sysinfo 1> $OUTPUT_DIR/virtual/virt_sysinfo.txt 2> /dev/null
		virsh net-list --all --name 1> $OUTPUT_DIR/virtual/virt_network_list.txt 2> /dev/null
		virsh nodeinfo 1> $OUTPUT_DIR/virtual/virt_nodeinfo.txt 2> /dev/null
		virsh pool-list --all 1> $OUTPUT_DIR/virtual/virt_pool_list.txt 2> /dev/null
		virsh net-list --all --details 1> $OUTPUT_DIR/virtual/virt_networks_detailed.txt 2> /dev/null
		virsh net-list --all --name 2>/dev/null | while read net; do
			if [ -n "$net" ]; then
				echo "=== Network: $net ===" >> $OUTPUT_DIR/virtual/virt_network_configs.txt
				virsh net-dumpxml "$net" >> $OUTPUT_DIR/virtual/virt_network_configs.txt 2> /dev/null
				virsh net-info "$net" >> $OUTPUT_DIR/virtual/virt_network_configs.txt 2> /dev/null
				virsh net-dhcp-leases "$net" >> $OUTPUT_DIR/virtual/virt_network_configs.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/virtual/virt_network_configs.txt
			fi
		done
		virsh pool-list --all --details 1> $OUTPUT_DIR/virtual/virt_storage_pools_detailed.txt 2> /dev/null
		virsh pool-list --all --name 2>/dev/null | while read pool; do
			if [ -n "$pool" ]; then
				echo "=== Storage Pool: $pool ===" >> $OUTPUT_DIR/virtual/virt_storage_pool_configs.txt
				virsh pool-dumpxml "$pool" >> $OUTPUT_DIR/virtual/virt_storage_pool_configs.txt 2> /dev/null
				virsh pool-info "$pool" >> $OUTPUT_DIR/virtual/virt_storage_pool_configs.txt 2> /dev/null
				virsh vol-list "$pool" --details >> $OUTPUT_DIR/virtual/virt_storage_pool_configs.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/virtual/virt_storage_pool_configs.txt
			fi
		done
		virsh list --all --name 2>/dev/null | while read vm; do
			if [ -n "$vm" ]; then
				echo "=== VM: $vm ===" >> $OUTPUT_DIR/virtual/virt_vm_details.txt
				virsh dominfo "$vm" >> $OUTPUT_DIR/virtual/virt_vm_details.txt 2> /dev/null
				virsh dumpxml "$vm" > $OUTPUT_DIR/virtual/virt_vm_${vm}_config.xml 2> /dev/null
				virsh domblklist "$vm" --details >> $OUTPUT_DIR/virtual/virt_vm_details.txt 2> /dev/null
				virsh domiflist "$vm" >> $OUTPUT_DIR/virtual/virt_vm_details.txt 2> /dev/null
				virsh vcpuinfo "$vm" >> $OUTPUT_DIR/virtual/virt_vm_details.txt 2> /dev/null
				virsh dommemstat "$vm" >> $OUTPUT_DIR/virtual/virt_vm_details.txt 2> /dev/null
				virsh domblkstat "$vm" --human >> $OUTPUT_DIR/virtual/virt_vm_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/virtual/virt_vm_details.txt
				virsh snapshot-list "$vm" --tree > $OUTPUT_DIR/virtual/virt_vm_${vm}_snapshots.txt 2> /dev/null
				virsh snapshot-list "$vm" --details >> $OUTPUT_DIR/virtual/virt_vm_${vm}_snapshots.txt 2> /dev/null
			fi
		done
		virsh capabilities > $OUTPUT_DIR/virtual/virt_capabilities.xml 2> /dev/null
		virsh domcapabilities > $OUTPUT_DIR/virtual/virt_domain_capabilities.xml 2> /dev/null
		virsh nodedev-list > $OUTPUT_DIR/virtual/virt_nodedev_list.txt 2> /dev/null
		virsh nodedev-list --tree > $OUTPUT_DIR/virtual/virt_nodedev_tree.txt 2> /dev/null
		virsh iface-list --all > $OUTPUT_DIR/virtual/virt_interfaces.txt 2> /dev/null
		virsh version > $OUTPUT_DIR/virtual/virt_version.txt 2> /dev/null
		virsh uri > $OUTPUT_DIR/virtual/virt_uri.txt 2> /dev/null
	fi

	# QEMU specific artifacts (often used with KVM)
	if [ -x "$(command -v qemu-img)" ]; then
		echo "  ${COL_ENTRY}>${RESET} Collecting QEMU disk information"
		# Common locations for QEMU/KVM images
		for dir in /var/lib/libvirt/images /var/lib/virt /var/lib/qemu; do
			if [ -d "$dir" ]; then
				find "$dir" \( -name "*.qcow2" -o -name "*.img" -o -name "*.raw" \) -type f 2>/dev/null | while read img; do
					echo "=== Image: $img ===" >> $OUTPUT_DIR/virtual/qemu_disk_info.txt
					qemu-img info "$img" >> $OUTPUT_DIR/virtual/qemu_disk_info.txt 2> /dev/null
					echo "" >> $OUTPUT_DIR/virtual/qemu_disk_info.txt
				done
			fi
		done
	fi

	# libvirt configuration files
	if [ -d "/etc/libvirt" ]; then
		echo "  ${COL_ENTRY}>${RESET} Collecting libvirt configurations"
		# List configuration files without copying sensitive content
		find /etc/libvirt -name "*.conf" -type f 2>/dev/null | while read conf; do
			echo "$conf" >> $OUTPUT_DIR/virtual/libvirt_config_files.txt
			ls -la "$conf" >> $OUTPUT_DIR/virtual/libvirt_config_files.txt
		done
		
		# libvirt logs location
		if [ -d "/var/log/libvirt" ]; then
			ls -la /var/log/libvirt/ > $OUTPUT_DIR/virtual/libvirt_log_listing.txt 2> /dev/null
			# Copy recent QEMU logs (last 7 days)
			find /var/log/libvirt/qemu -name "*.log" -mtime -7 -type f 2>/dev/null | while read log; do
				cp "$log" "$OUTPUT_DIR/virtual/" 2> /dev/null
			done
		fi
	fi

    # vmctl 
	if [ -x "$(command -v vmctl)" ]
	then
		vmctl status 1> $OUTPUT_DIR/virtual/vmctl_status.txt 2> /dev/null
	fi
    # vim-cmd  
	if [ -x "$(command -v vim-cmd )" ]
	then
		vim-cmd vmsvc/getallvms 1> $OUTPUT_DIR/virtual/vim-cmd_getallvms.txt 2> /dev/null
	fi
    # qm 
	if [ -x "$(command -v qm )" ]
	then
		qm list 1> $OUTPUT_DIR/virtual/proxmox_qm_list.txt 2> /dev/null		
	fi

	if [ -d "/var/lib/hyperv" ] || [ -x "$(command -v hvc)" ]; then
		echo "  ${COL_ENTRY}>${RESET} Hyper-V artifacts"
		
		# Hyper-V services
		systemctl status hyperv* > $OUTPUT_DIR/virtual/hyperv_services.txt 2> /dev/null
		
		# Hyper-V kernel modules
		lsmod | grep -E "hv_|hyperv" > $OUTPUT_DIR/virtual/hyperv_modules.txt 2> /dev/null
		
		# Integration services
		if [ -d "/sys/bus/vmbus/devices" ]; then
			ls -la /sys/bus/vmbus/devices/ > $OUTPUT_DIR/virtual/hyperv_vmbus_devices.txt 2> /dev/null
		fi
	fi
	
	if [ -x "$(command -v xl)" ] || [ -x "$(command -v xm)" ]; then
		echo "  ${COL_ENTRY}>${RESET} Xen hypervisor collection"
		
		# Xen domains
		xl list -l 1> $OUTPUT_DIR/virtual/xen_domains.txt 2> /dev/null
		xl info 1> $OUTPUT_DIR/virtual/xen_info.txt 2> /dev/null
		xl dmesg 1> $OUTPUT_DIR/virtual/xen_dmesg.txt 2> /dev/null
		
		# Xen networking
		xl network-list 1> $OUTPUT_DIR/virtual/xen_networks.txt 2> /dev/null
		
		# Xen configuration
		if [ -d "/etc/xen" ]; then
			find /etc/xen -name "*.cfg" -type f | while read cfg; do
				echo "=== Config: $cfg ===" >> $OUTPUT_DIR/virtual/xen_configs.txt
				cat "$cfg" >> $OUTPUT_DIR/virtual/xen_configs.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/virtual/xen_configs.txt
			done
		fi
	fi

fi

# ---------------------------
# PART 10: CONTAINER INFORMATION
# ---------------------------

if [ -x "$(command -v containerd)" -o -x "$(command -v docker)" -o -x "$(command -v lxc)" -o -x "$(command -v pct)" -o -x "$(command -v podman)" ]
then
    echo "${COL_SECTION}CONTAINER INFORMATION [96% ]:${RESET}"
	mkdir $OUTPUT_DIR/containers
    if [ -x "$(command -v containerd)" ]
	then
	    echo "  ${COL_ENTRY}>${RESET} Collecting containerd config"
		containerd config dump 1> $OUTPUT_DIR/containers/containerd_config_all.txt 2> /dev/null
		containerd -v 1> $OUTPUT_DIR/containers/containerd_config_all.txt 2> /dev/null
	fi
	
	if [ -x "$(command -v docker)" ]
	then
	    echo "  ${COL_ENTRY}>${RESET} Collecting docker information"
		docker container ls --all --size 1> $OUTPUT_DIR/containers/docker_all_containers.txt 2> /dev/null
		docker image ls --all 1> $OUTPUT_DIR/containers/docker_all_images.txt 2> /dev/null
		docker info 1> $OUTPUT_DIR/containers/docker_info.txt 2> /dev/null
		docker version 1> $OUTPUT_DIR/containers/docker_version.txt 2> /dev/null
		docker network ls 1> $OUTPUT_DIR/containers/docker_network.txt 2> /dev/null
		docker stats --all --no-stream --no-trunc 1> $OUTPUT_DIR/containers/docker_stats.txt 2> /dev/null
		docker volume ls 1> $OUTPUT_DIR/containers/docker_volume.txt 2> /dev/null
		docker container ps --all | sed 1d | awk '{print $1}' 1>> $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null
		while read -r containerid; do docker container logs "$containerid" 1>> $OUTPUT_DIR/containers/docker_logs_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null
		while read -r containerid; do docker inspect "$containerid" 1>> $OUTPUT_DIR/containers/docker_inspect_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null
		while read -r containerid; do docker top "$containerid" 1>> $OUTPUT_DIR/containers/docker_processes_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null
		while read -r containerid; do docker network inspect "$containerid" 1>> $OUTPUT_DIR/containers/docker_network_config_inspect_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null
		while read -r containerid; do docker volume inspect "$containerid" 1>> $OUTPUT_DIR/containers/docker_volume_inspect_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null
		while read -r containerid; do docker diff "$containerid" 1>> $OUTPUT_DIR/containers/docker_filesystem_diff_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null
	fi
	
	if [ -x "$(command -v lxc)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting LXC information"
		lxc list --all-projects --format compact 1> $OUTPUT_DIR/containers/lxc_all_containers_and_vms.txt 2> /dev/null
		lxc image list --format compact 1> $OUTPUT_DIR/containers/lxc_images.txt 2> /dev/null
		lxc info 1> $OUTPUT_DIR/containers/lxc_info.txt 2> /dev/null
		lxc profile list --format compact 1> $OUTPUT_DIR/containers/lxc_profiles.txt 2> /dev/null
		lxc storage list --format compact 1> $OUTPUT_DIR/containers/lxc_storage.txt 2> /dev/null
		lxc warning list --format compact 1> $OUTPUT_DIR/containers/lxc_warnings.txt 2> /dev/null
		lxc version 1> $OUTPUT_DIR/containers/lxc_version.txt 2> /dev/null
		lxc list --all-projects --format json 1> $OUTPUT_DIR/containers/lxc_all_containers_json.txt 2> /dev/null
		lxc list --all-projects --format yaml 1> $OUTPUT_DIR/containers/lxc_all_containers_yaml.txt 2> /dev/null
		lxc network list 1> $OUTPUT_DIR/containers/lxc_network_list.txt 2> /dev/null
		lxc network list --format yaml 1> $OUTPUT_DIR/containers/lxc_network_list_yaml.txt 2> /dev/null
		lxc remote list 1> $OUTPUT_DIR/containers/lxc_remote_list.txt 2> /dev/null
		lxc cluster list 2>/dev/null 1> $OUTPUT_DIR/containers/lxc_cluster_list.txt
		lxc cluster show 2>/dev/null 1> $OUTPUT_DIR/containers/lxc_cluster_info.txt
		lxc operation list 1> $OUTPUT_DIR/containers/lxc_operations.txt 2> /dev/null
		lxc config trust list 1> $OUTPUT_DIR/containers/lxc_certificates.txt 2> /dev/null
		lxc alias list 1> $OUTPUT_DIR/containers/lxc_aliases.txt 2> /dev/null
		lxc list --all-projects --format compact | sed 1d | awk '{print $1"|"$2}' | while IFS='|' read -r name project; do
			if [ -n "$name" ]; then
				echo "$name" >> $OUTPUT_DIR/containers/lxc_container_ids.txt
			fi
		done
		while read -r containerid; do
			if [ -n "$containerid" ]; then
				echo "=== Container/VM: $containerid ===" >> $OUTPUT_DIR/containers/lxc_container_details.txt
				lxc info "$containerid" --show-log >> $OUTPUT_DIR/containers/lxc_container_details.txt 2> /dev/null
				echo "--- Configuration ---" >> $OUTPUT_DIR/containers/lxc_container_details.txt
				lxc config show "$containerid" >> $OUTPUT_DIR/containers/lxc_container_details.txt 2> /dev/null
				echo "--- Devices ---" >> $OUTPUT_DIR/containers/lxc_container_details.txt
				lxc config device list "$containerid" >> $OUTPUT_DIR/containers/lxc_container_details.txt 2> /dev/null
				echo "--- Resources ---" >> $OUTPUT_DIR/containers/lxc_container_details.txt
				lxc info "$containerid" --resources >> $OUTPUT_DIR/containers/lxc_container_details.txt 2> /dev/null
				echo "--- Snapshots ---" >> $OUTPUT_DIR/containers/lxc_container_details.txt
				lxc info "$containerid" | grep -A 50 "Snapshots:" >> $OUTPUT_DIR/containers/lxc_container_details.txt 2> /dev/null
				echo "--- Processes ---" >> $OUTPUT_DIR/containers/lxc_container_details.txt
				lxc info "$containerid" | grep -A 20 "Processes:" >> $OUTPUT_DIR/containers/lxc_container_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/lxc_container_details.txt
				lxc config show "$containerid" --expanded > "$OUTPUT_DIR/containers/lxc_config_expanded_${containerid}.yaml" 2> /dev/null
				lxc info "$containerid" --show-log > "$OUTPUT_DIR/containers/lxc_info_log_${containerid}.txt" 2> /dev/null
				lxc file pull "$containerid/etc/passwd" - > "$OUTPUT_DIR/containers/lxc_${containerid}_passwd.txt" 2> /dev/null
				lxc snapshot list "$containerid" > "$OUTPUT_DIR/containers/lxc_snapshots_${containerid}.txt" 2> /dev/null
				lxc config metadata show "$containerid" > "$OUTPUT_DIR/containers/lxc_metadata_${containerid}.yaml" 2> /dev/null
			fi
		done < $OUTPUT_DIR/containers/lxc_container_ids.txt 2> /dev/null
		lxc network list --format compact | sed 1d | awk '{print $1}' | while read netname; do
			if [ -n "$netname" ]; then
				echo "=== Network: $netname ===" >> $OUTPUT_DIR/containers/lxc_network_configs.txt
				lxc network show "$netname" >> $OUTPUT_DIR/containers/lxc_network_configs.txt 2> /dev/null
				lxc network info "$netname" >> $OUTPUT_DIR/containers/lxc_network_configs.txt 2> /dev/null
				lxc network list-leases "$netname" >> $OUTPUT_DIR/containers/lxc_network_configs.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/lxc_network_configs.txt
			fi
		done
		lxc profile list --format compact | sed 1d | awk '{print $1}' | while read profile; do
			if [ -n "$profile" ]; then
				echo "=== Profile: $profile ===" >> $OUTPUT_DIR/containers/lxc_profile_configs.txt
				lxc profile show "$profile" >> $OUTPUT_DIR/containers/lxc_profile_configs.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/lxc_profile_configs.txt
			fi
		done
		lxc storage list --format compact | sed 1d | awk '{print $1}' 1> $OUTPUT_DIR/containers/lxc_storage_ids.txt 2> /dev/null
		while read -r storageid; do
			if [ -n "$storageid" ]; then
				echo "=== Storage: $storageid ===" >> $OUTPUT_DIR/containers/lxc_storage_details.txt
				lxc storage show "$storageid" >> $OUTPUT_DIR/containers/lxc_storage_details.txt 2> /dev/null
				lxc storage info "$storageid" >> $OUTPUT_DIR/containers/lxc_storage_details.txt 2> /dev/null
				lxc storage volume list "$storageid" >> $OUTPUT_DIR/containers/lxc_storage_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/lxc_storage_details.txt
			fi
		done < $OUTPUT_DIR/containers/lxc_storage_ids.txt 2> /dev/null
		lxc image list --format compact | sed 1d | awk '{print $2}' | while read imageid; do
			if [ -n "$imageid" ]; then
				echo "=== Image: $imageid ===" >> $OUTPUT_DIR/containers/lxc_image_details.txt
				lxc image info "$imageid" >> $OUTPUT_DIR/containers/lxc_image_details.txt 2> /dev/null
				lxc image show "$imageid" >> $OUTPUT_DIR/containers/lxc_image_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/lxc_image_details.txt
			fi
		done
		lxc config show 1> $OUTPUT_DIR/containers/lxc_global_config.txt 2> /dev/null
		lxc monitor --type=lifecycle --pretty 2>&1 | timeout 2 cat > $OUTPUT_DIR/containers/lxc_monitor_sample.txt 2> /dev/null
		if [ -d "/var/lib/lxd" ]; then
			ls -la /var/lib/lxd/ > $OUTPUT_DIR/containers/lxc_var_lib_listing.txt 2> /dev/null
			find /var/lib/lxd/logs -name "*.log" -type f -mtime -7 2>/dev/null | head -50 > $OUTPUT_DIR/containers/lxc_recent_logs.txt
		fi
		if [ -d "/var/log/lxd" ]; then
			ls -la /var/log/lxd/ > $OUTPUT_DIR/containers/lxc_log_listing.txt 2> /dev/null
		fi
		# Legacy LXC check (non-LXD)
		if [ -x "$(command -v lxc-ls)" ]; then
			echo "  ${COL_ENTRY}>${RESET} Collecting legacy LXC information"
			lxc-ls -f 1> $OUTPUT_DIR/containers/legacy_lxc_list.txt 2> /dev/null
			lxc-checkconfig 1> $OUTPUT_DIR/containers/legacy_lxc_checkconfig.txt 2> /dev/null
			if [ -d "/var/lib/lxc" ]; then
				ls -la /var/lib/lxc/ > $OUTPUT_DIR/containers/legacy_lxc_containers.txt 2> /dev/null
				find /var/lib/lxc -name "config" -type f 2>/dev/null | while read cfg; do
					echo "=== Config: $cfg ===" >> $OUTPUT_DIR/containers/legacy_lxc_configs.txt
					cat "$cfg" >> $OUTPUT_DIR/containers/legacy_lxc_configs.txt 2> /dev/null
					echo "" >> $OUTPUT_DIR/containers/legacy_lxc_configs.txt
				done
			fi
		fi
	fi
	
	if [ -x "$(command -v pct)" ]
	then
	    echo "  ${COL_ENTRY}>${RESET} Collecting PROXMOX information"
		pct list 1> $OUTPUT_DIR/containers/proxmox_container_list.txt 2> /dev/null
		pct cpusets 1> $OUTPUT_DIR/containers/proxmox_cpuset.txt 2> /dev/null
		pct list | sed -e '1d' | awk '{print $1}' 1>> $OUTPUT_DIR/containers/proxmox_container_ids.txt 2> /dev/null
		while read -r containerid; do pct config "$containerid" --current 1>> $OUTPUT_DIR/containers/proxmox_config_details_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/proxmox_container_ids.txt 2> /dev/null
		while read -r containerid; do pct listsnapshot "$containerid" 1>> $OUTPUT_DIR/containers/proxmox_listsnapshot_details_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/proxmox_container_ids.txt 2> /dev/null
	fi
	
	if [ -x "$(command -v podman)" ]
	then
	    echo "  ${COL_ENTRY}>${RESET} Collecting PODMAN information"
		podman container ls --all --size 1> $OUTPUT_DIR/containers/podman_container_list.txt 2> /dev/null
		podman image ls --all 1> $OUTPUT_DIR/containers/podman_image_list.txt 2> /dev/null
		podman version 1> $OUTPUT_DIR/containers/podman_version.txt 2> /dev/null
		podman network ls 1> $OUTPUT_DIR/containers/podman_networks.txt 2> /dev/null
		podman volume ls 1> $OUTPUT_DIR/containers/podman_volumes.txt 2> /dev/null
		podman container ps --all | sed 1d | awk '{print $1}' 1> $OUTPUT_DIR/containers/podman_container_ids.txt 2> /dev/null
		while read -r containerid; do podman container logs "$containerid" --current 1>> $OUTPUT_DIR/containers/podman_logs_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/podman_container_ids.txt 2> /dev/null
		while read -r containerid; do podman inspect "$containerid" 1>> $OUTPUT_DIR/containers/podman_inspect_details_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/podman_container_ids.txt 2> /dev/null
		while read -r containerid; do podman network inspect "$containerid" --current 1>> $OUTPUT_DIR/containers/podman_network_details_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/podman_container_ids.txt 2> /dev/null
		while read -r containerid; do podman top "$containerid" 1>> $OUTPUT_DIR/containers/podman_process_details_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/podman_container_ids.txt 2> /dev/null
		while read -r containerid; do podman diff "$containerid" --current 1>> $OUTPUT_DIR/containers/podman_filesystem_diff_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/podman_container_ids.txt 2> /dev/null
		podman volume ls | sed 1d | awk '{print $2}' 1> $OUTPUT_DIR/containers/podman_storage_ids.txt 2> /dev/null 
		while read -r containerid; do podman volume inspect "$containerid" 1>> $OUTPUT_DIR/containers/podman_volume_details_$containerid.txt 2> /dev/null; done < $OUTPUT_DIR/containers/podman_storage_ids.txt 2> /dev/null
		
	fi
fi

# --------------------------------
# PART 11: CLEANUP / CREATE ARCHIVE
# --------------------------------

echo "${COL_SECTION}FINISHING [100%]:${RESET}"

echo "  ${COL_ENTRY}>${RESET} Removing empty files"
for REMOVELIST in `find $OUTPUT_DIR -size 0`
do
    rm -rf $REMOVELIST 2> /dev/null
done

echo "  ${COL_ENTRY}>${RESET} Removing oversize file list"
for REMOVELISTOVERSIZED in `find $OUTPUT_DIR -name oversized_files.txt`
do
    rm -rf $REMOVELISTOVERSIZED 2> /dev/null
done

echo "  ${COL_ENTRY}>${RESET} Creating TAR file"
tar cJf $TAR_FILE.xz $OUTPUT_DIR 1> /dev/null  2> /dev/null || tar cjf $TAR_FILE.bz2 $OUTPUT_DIR 1> /dev/null  2> /dev/null || tar zcf $TAR_FILE.gz $OUTPUT_DIR 1> /dev/null  2> /dev/null || tar cf $TAR_FILE $OUTPUT_DIR 1> /dev/null  2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Removing temporary directory"
chflags -R noschg $OUTPUT_DIR 1> /dev/null  2> /dev/null
rm -rf $OUTPUT_DIR

echo ""
echo "Finished! Copy the audit file ${TAR_FILE} to a safe location. Happy hunting."
echo "${RESET}"

exit 0
