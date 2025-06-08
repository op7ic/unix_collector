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

echo "  ${COL_ENTRY}>${RESET} Enhanced process information"
mkdir -p $OUTPUT_DIR/process_info/maps
mkdir -p $OUTPUT_DIR/process_info/limits
mkdir -p $OUTPUT_DIR/process_info/environ

for pid in /proc/[0-9]*; do
    PID_NUM=$(basename $pid)
    cat $pid/maps > $OUTPUT_DIR/process_info/maps/maps_${PID_NUM}.txt 2>/dev/null
    cat $pid/limits > $OUTPUT_DIR/process_info/limits/limits_${PID_NUM}.txt 2>/dev/null
    cat $pid/environ | tr '\0' '\n' > $OUTPUT_DIR/process_info/environ/environ_${PID_NUM}.txt 2>/dev/null
    cat $pid/smaps > $OUTPUT_DIR/process_info/maps/smaps_${PID_NUM}.txt 2>/dev/null
    ls -la $pid/fd > $OUTPUT_DIR/process_info/fd_detailed_${PID_NUM}.txt 2>/dev/null
done

echo "  ${COL_ENTRY}>${RESET} Process network namespaces"
for pid in /proc/[0-9]*; do
    PID_NUM=$(basename $pid)
    if [ -d "$pid/net" ]; then
        cat $pid/net/tcp > $OUTPUT_DIR/process_info/net_tcp_${PID_NUM}.txt 2>/dev/null
        cat $pid/net/udp > $OUTPUT_DIR/process_info/net_udp_${PID_NUM}.txt 2>/dev/null
    fi
done

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

echo "  ${COL_ENTRY}>${RESET} Systemd timers and services"
mkdir -p $OUTPUT_DIR/general/systemd
systemctl list-timers --all --no-pager > $OUTPUT_DIR/general/systemd/timers_all.txt 2>/dev/null
systemctl list-units --all --no-pager > $OUTPUT_DIR/general/systemd/units_all.txt 2>/dev/null
systemctl list-units --failed --no-pager > $OUTPUT_DIR/general/systemd/units_failed.txt 2>/dev/null
systemctl list-unit-files --type=service --no-pager > $OUTPUT_DIR/general/systemd/services_all.txt 2>/dev/null
journalctl -n 1000 --no-pager > $OUTPUT_DIR/general/systemd/journal_recent.txt 2>/dev/null
journalctl -b --no-pager > $OUTPUT_DIR/general/systemd/journal_boot.txt 2>/dev/null
mkdir -p $OUTPUT_DIR/general/systemd/timers
find /etc/systemd /usr/lib/systemd /lib/systemd -name "*.timer" -type f 2>/dev/null | while read timer; do
    cp "$timer" $OUTPUT_DIR/general/systemd/timers/ 2>/dev/null
done

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

echo "  ${COL_ENTRY}>${RESET} Kernel Modules and Verification"
mkdir $OUTPUT_DIR/general/kernel_modules 2> /dev/null

if [ $PLATFORM = "solaris" ]
then
    modinfo 1> $OUTPUT_DIR/general/kernel_modules/modinfo.txt 2> /dev/null
    # Get detailed module information
    modinfo | tail -n +2 | awk '{print $1}' | while read mod_id
    do
        echo "=== Module ID: $mod_id ===" 1>> $OUTPUT_DIR/general/kernel_modules/module_details.txt 2> /dev/null
        modinfo -c -i $mod_id 1>> $OUTPUT_DIR/general/kernel_modules/module_details.txt 2> /dev/null
        echo "" 1>> $OUTPUT_DIR/general/kernel_modules/module_details.txt 2> /dev/null
    done
    # List module paths
    find /kernel /usr/kernel -name "*.ko" -o -name "drv/*" 1> $OUTPUT_DIR/general/kernel_modules/module_paths.txt 2> /dev/null
    # Verify module checksums
    pkg verify -v 2> /dev/null | grep "/kernel/" 1> $OUTPUT_DIR/general/kernel_modules/kernel_file_verification.txt 2> /dev/null
elif [ $PLATFORM = "linux" ]
then
    lsmod 1> $OUTPUT_DIR/general/kernel_modules/lsmod.txt 2> /dev/null
    # Check secure boot status
    if [ -d /sys/firmware/efi ]
    then
        if [ -f /sys/firmware/efi/vars/SecureBoot-*/data ]
        then
            od -An -t u1 /sys/firmware/efi/vars/SecureBoot-*/data 1> $OUTPUT_DIR/general/kernel_modules/secure_boot_raw.txt 2> /dev/null
        fi
        if [ -x /usr/bin/mokutil ]
        then
            mokutil --sb-state 1> $OUTPUT_DIR/general/kernel_modules/secure_boot_status.txt 2> /dev/null
        fi
    fi
    # Get detailed module information
    if [ -x /sbin/modinfo -o -x /usr/sbin/modinfo ]
    then
        lsmod | tail -n +2 | awk '{print $1}' | while read module
        do
            echo "=== Module: $module ===" 1>> $OUTPUT_DIR/general/kernel_modules/modinfo_all.txt 2> /dev/null
            modinfo $module 1>> $OUTPUT_DIR/general/kernel_modules/modinfo_all.txt 2> /dev/null
            echo "" 1>> $OUTPUT_DIR/general/kernel_modules/modinfo_all.txt 2> /dev/null
            # Get module parameters
            if [ -d /sys/module/$module/parameters ]
            then
                echo "=== Parameters for $module ===" 1>> $OUTPUT_DIR/general/kernel_modules/module_parameters.txt 2> /dev/null
                ls /sys/module/$module/parameters/ 2> /dev/null | while read param
                do
                    echo -n "$param = " 1>> $OUTPUT_DIR/general/kernel_modules/module_parameters.txt 2> /dev/null
                    cat /sys/module/$module/parameters/$param 1>> $OUTPUT_DIR/general/kernel_modules/module_parameters.txt 2> /dev/null || echo "unreadable" 1>> $OUTPUT_DIR/general/kernel_modules/module_parameters.txt 2> /dev/null
                done
                echo "" 1>> $OUTPUT_DIR/general/kernel_modules/module_parameters.txt 2> /dev/null
            fi
        done
    fi
    # Check module taint status
    for module_dir in /sys/module/*
    do
        if [ -f "$module_dir/taint" ]
        then
            module_name=`basename $module_dir`
            taint_value=`cat $module_dir/taint 2> /dev/null`
            if [ "$taint_value" != "0" ] && [ ! -z "$taint_value" ]
            then
                echo "$module_name: taint=$taint_value" 1>> $OUTPUT_DIR/general/kernel_modules/tainted_modules.txt 2> /dev/null
            fi
        fi
    done
    # Check module signature enforcement
    if [ -f /proc/sys/kernel/modules_disabled ]
    then
        echo "modules_disabled = `cat /proc/sys/kernel/modules_disabled`" 1> $OUTPUT_DIR/general/kernel_modules/module_loading_restrictions.txt 2> /dev/null
    fi
    if [ -f /proc/sys/kernel/kexec_load_disabled ]
    then
        echo "kexec_load_disabled = `cat /proc/sys/kernel/kexec_load_disabled`" 1>> $OUTPUT_DIR/general/kernel_modules/module_loading_restrictions.txt 2> /dev/null
    fi
    if [ -f /proc/sys/kernel/module.sig_enforce ]
    then
        echo "module.sig_enforce = `cat /proc/sys/kernel/module.sig_enforce`" 1>> $OUTPUT_DIR/general/kernel_modules/module_loading_restrictions.txt 2> /dev/null
    fi
    # Find loaded module files and hash them
    find /lib/modules/`uname -r` -name "*.ko" -o -name "*.ko.xz" -o -name "*.ko.gz" 2> /dev/null | head -100 | while read module_file
    do
        module_name=`basename $module_file | sed 's/\.\(ko\|ko\.xz\|ko\.gz\)$//'`
        # Check if module is currently loaded
        if lsmod | grep -q "^$module_name "
        then
            echo "$module_file (LOADED)" 1>> $OUTPUT_DIR/general/kernel_modules/loaded_module_paths.txt 2> /dev/null
            # Get file hash
            if [ -x /usr/bin/sha256sum ]
            then
                sha256sum "$module_file" 1>> $OUTPUT_DIR/general/kernel_modules/module_hashes.txt 2> /dev/null
            elif [ -x /usr/bin/sha1sum ]
            then
                sha1sum "$module_file" 1>> $OUTPUT_DIR/general/kernel_modules/module_hashes.txt 2> /dev/null
            elif [ -x /usr/bin/md5sum ]
            then
                md5sum "$module_file" 1>> $OUTPUT_DIR/general/kernel_modules/module_hashes.txt 2> /dev/null
            fi
        fi
    done
    # Check for out-of-tree modules
    find /lib/modules/`uname -r` -name "*.ko" -path "*/extra/*" -o -path "*/updates/*" 1> $OUTPUT_DIR/general/kernel_modules/out_of_tree_modules.txt 2> /dev/null
    # List module dependencies
    lsmod | tail -n +2 | awk '{print $1}' | while read module
    do
        echo -n "$module: " 1>> $OUTPUT_DIR/general/kernel_modules/module_dependencies.txt 2> /dev/null
        modinfo -F depends $module 1>> $OUTPUT_DIR/general/kernel_modules/module_dependencies.txt 2> /dev/null || echo "unknown" 1>> $OUTPUT_DIR/general/kernel_modules/module_dependencies.txt 2> /dev/null
    done
    # Check for hidden modules
    cat /proc/modules | awk '{print $1}' | sort 1> $OUTPUT_DIR/general/kernel_modules/proc_modules.txt 2> /dev/null
    lsmod | tail -n +2 | awk '{print $1}' | sort 1> $OUTPUT_DIR/general/kernel_modules/lsmod_modules.txt 2> /dev/null
    diff $OUTPUT_DIR/general/kernel_modules/proc_modules.txt $OUTPUT_DIR/general/kernel_modules/lsmod_modules.txt 1> $OUTPUT_DIR/general/kernel_modules/module_discrepancies.txt 2> /dev/null
    # Check sysfs vs proc
    ls /sys/module/ | grep -v "^builtin$" | sort 1> $OUTPUT_DIR/general/kernel_modules/sysfs_modules.txt 2> /dev/null
    diff $OUTPUT_DIR/general/kernel_modules/proc_modules.txt $OUTPUT_DIR/general/kernel_modules/sysfs_modules.txt 1>> $OUTPUT_DIR/general/kernel_modules/module_discrepancies.txt 2> /dev/null
elif [ $PLATFORM = "android" ]
then
    lsmod 1> $OUTPUT_DIR/general/kernel_modules/lsmod.txt 2> /dev/null
    ls -la /sys/module/ 1> $OUTPUT_DIR/general/kernel_modules/sys_modules.txt 2> /dev/null
    ls -la /system/lib/modules/ 1> $OUTPUT_DIR/general/kernel_modules/system_lib_modules.txt 2> /dev/null
    ls -la /vendor/lib/modules/ 1> $OUTPUT_DIR/general/kernel_modules/vendor_lib_modules.txt 2> /dev/null
    # Check for Magisk modules
    if [ -d /data/adb/modules ]
    then
        ls -la /data/adb/modules/ 1> $OUTPUT_DIR/general/kernel_modules/magisk_modules.txt 2> /dev/null
    fi
    # Module info if available
    if [ -x /system/bin/modinfo ]
    then
        lsmod | tail -n +2 | awk '{print $1}' | while read module
        do
            echo "=== Module: $module ===" 1>> $OUTPUT_DIR/general/kernel_modules/modinfo_all.txt 2> /dev/null
            modinfo $module 1>> $OUTPUT_DIR/general/kernel_modules/modinfo_all.txt 2> /dev/null
            echo "" 1>> $OUTPUT_DIR/general/kernel_modules/modinfo_all.txt 2> /dev/null
        done
    fi
elif [ $PLATFORM = "mac" ]
then
    kextstat 1> $OUTPUT_DIR/general/kernel_modules/kextstat.txt 2> /dev/null
    kmutil showloaded 1> $OUTPUT_DIR/general/kernel_modules/kmutil_showloaded.txt 2> /dev/null
    # Get detailed kext information
    kextstat | tail -n +2 | awk '{print $6}' | while read kext_id
    do
        echo "=== Kext: $kext_id ===" 1>> $OUTPUT_DIR/general/kernel_modules/kext_info_all.txt 2> /dev/null
        kextutil -show-diagnostics $kext_id 1>> $OUTPUT_DIR/general/kernel_modules/kext_info_all.txt 2> /dev/null
        echo "" 1>> $OUTPUT_DIR/general/kernel_modules/kext_info_all.txt 2> /dev/null
    done
    # Verify kext signatures
    find /System/Library/Extensions /Library/Extensions -name "*.kext" -maxdepth 1 2> /dev/null | while read kext_path
    do
        kext_name=`basename "$kext_path"`
        echo "=== $kext_name ===" 1>> $OUTPUT_DIR/general/kernel_modules/kext_signatures.txt 2> /dev/null
        codesign -dvvv "$kext_path" 1>> $OUTPUT_DIR/general/kernel_modules/kext_signatures.txt 2> /dev/null
        echo "" 1>> $OUTPUT_DIR/general/kernel_modules/kext_signatures.txt 2> /dev/null
    done
    # Check system integrity protection
    csrutil status 1> $OUTPUT_DIR/general/kernel_modules/sip_status.txt 2> /dev/null
    # Check for unsigned kexts
    kextfind -not -authentic 1> $OUTPUT_DIR/general/kernel_modules/unsigned_kexts.txt 2> /dev/null
    # Kernel extension cache info
    kextcache -showinfo 1> $OUTPUT_DIR/general/kernel_modules/kextcache_info.txt 2> /dev/null
elif [ $PLATFORM = "aix" ]
then
    genkex 1> $OUTPUT_DIR/general/kernel_modules/genkex.txt 2> /dev/null
    # List kernel extension files
    find /usr/lib/drivers -name "*.ext" 1> $OUTPUT_DIR/general/kernel_modules/driver_files.txt 2> /dev/null
    # Check trusted computing base
    trustchk -n ALL 1> $OUTPUT_DIR/general/kernel_modules/trustchk.txt 2> /dev/null
elif [ $PLATFORM = "hpux" ]
then
    # HP-UX kernel modules
    kmadmin -s 1> $OUTPUT_DIR/general/kernel_modules/kmadmin.txt 2> /dev/null
    kcmodule 1> $OUTPUT_DIR/general/kernel_modules/kcmodule.txt 2> /dev/null
    kctune 1> $OUTPUT_DIR/general/kernel_modules/kctune.txt 2> /dev/null
else
    # Generic/BSD platforms
    if [ -x /sbin/kldstat ]
    then
        kldstat 1> $OUTPUT_DIR/general/kernel_modules/kldstat.txt 2> /dev/null
        # Get detailed module information
        kldstat | tail -n +2 | awk '{print $5}' | while read module
        do
            echo "=== Module: $module ===" 1>> $OUTPUT_DIR/general/kernel_modules/module_info.txt 2> /dev/null
            kldstat -v -n $module 1>> $OUTPUT_DIR/general/kernel_modules/module_info.txt 2> /dev/null
            echo "" 1>> $OUTPUT_DIR/general/kernel_modules/module_info.txt 2> /dev/null
        done
        # List available modules
        find /boot/kernel /boot/modules -name "*.ko" 1> $OUTPUT_DIR/general/kernel_modules/available_modules.txt 2> /dev/null
    else
        # Fallback to basic lsmod
        lsmod 1> $OUTPUT_DIR/general/kernel_modules/lsmod.txt 2> /dev/null
    fi
fi
# Count modules if possible
if [ -f $OUTPUT_DIR/general/kernel_modules/lsmod.txt ]
then
    MODULE_COUNT=`cat $OUTPUT_DIR/general/kernel_modules/lsmod.txt | wc -l`
    MODULE_COUNT=`expr $MODULE_COUNT - 1`
    echo "Total Loaded Modules: $MODULE_COUNT" 1>> $OUTPUT_DIR/general/kernel_modules/verification_summary.txt 2> /dev/null
fi

if [ -f $OUTPUT_DIR/general/kernel_modules/tainted_modules.txt ]
then
    TAINTED_COUNT=`cat $OUTPUT_DIR/general/kernel_modules/tainted_modules.txt | wc -l`
    echo "Tainted Modules: $TAINTED_COUNT" 1>> $OUTPUT_DIR/general/kernel_modules/verification_summary.txt 2> /dev/null
fi


# Systemd journal logs
if [ -x "$(command -v journalctl)" ]; then
    echo "  ${COL_ENTRY}>${RESET} Systemd journal logs"
    journalctl --no-pager -n 10000 > $OUTPUT_DIR/logs/journal_recent.txt 2>/dev/null
    journalctl --no-pager -b > $OUTPUT_DIR/logs/journal_boot.txt 2>/dev/null
    journalctl --no-pager -p err > $OUTPUT_DIR/logs/journal_errors.txt 2>/dev/null
fi

echo "  ${COL_ENTRY}>${RESET} User Activity and Authentication Logs"
mkdir $OUTPUT_DIR/user_activity 2> /dev/null

# Collect login/logout records
echo "    Collecting login records..."
if [ $PLATFORM = "linux" -o $PLATFORM = "generic" ]
then
    # Copy raw wtmp/btmp/utmp files
    if [ -f /var/log/wtmp ]; then
        cp /var/log/wtmp $OUTPUT_DIR/user_activity/wtmp.raw 2> /dev/null
        last -f /var/log/wtmp 1> $OUTPUT_DIR/user_activity/last-wtmp.txt 2> /dev/null
        last -f /var/log/wtmp -x 1> $OUTPUT_DIR/user_activity/last-wtmp-extended.txt 2> /dev/null
    fi
    if [ -f /var/log/btmp ]; then
        cp /var/log/btmp $OUTPUT_DIR/user_activity/btmp.raw 2> /dev/null
        lastb -f /var/log/btmp 1> $OUTPUT_DIR/user_activity/lastb-failed-logins.txt 2> /dev/null
        last -f /var/log/btmp 1> $OUTPUT_DIR/user_activity/last-btmp.txt 2> /dev/null
    fi
    if [ -f /var/run/utmp ]; then
        cp /var/run/utmp $OUTPUT_DIR/user_activity/utmp.raw 2> /dev/null
        who -a /var/run/utmp 1> $OUTPUT_DIR/user_activity/who-utmp.txt 2> /dev/null
    fi
    if [ -f /var/log/lastlog ]; then
        cp /var/log/lastlog $OUTPUT_DIR/user_activity/lastlog.raw 2> /dev/null
        lastlog 1> $OUTPUT_DIR/user_activity/lastlog.txt 2> /dev/null
        lastlog -u 0-99999 1> $OUTPUT_DIR/user_activity/lastlog-all-users.txt 2> /dev/null
    fi
    # Collect rotated wtmp files
    for wtmp_file in /var/log/wtmp.*
    do
        if [ -f "$wtmp_file" ]; then
            filename=`basename $wtmp_file`
            cp $wtmp_file $OUTPUT_DIR/user_activity/${filename}.raw 2> /dev/null
            last -f $wtmp_file 1> $OUTPUT_DIR/user_activity/last-${filename}.txt 2> /dev/null
        fi
    done
    # Additional login records
    w 1> $OUTPUT_DIR/user_activity/w-current-users.txt 2> /dev/null
    who -a 1> $OUTPUT_DIR/user_activity/who-all.txt 2> /dev/null
    users 1> $OUTPUT_DIR/user_activity/users.txt 2> /dev/null
    ac -p 1> $OUTPUT_DIR/user_activity/ac-user-connect-time.txt 2> /dev/null
    ac -d 1> $OUTPUT_DIR/user_activity/ac-daily-connect-time.txt 2> /dev/null
elif [ $PLATFORM = "solaris" ]
then
    # Solaris login records
    if [ -f /var/adm/wtmpx ]; then
        cp /var/adm/wtmpx $OUTPUT_DIR/user_activity/wtmpx.raw 2> /dev/null
        last -f /var/adm/wtmpx 1> $OUTPUT_DIR/user_activity/last-wtmpx.txt 2> /dev/null
    fi
    if [ -f /var/adm/lastlog ]; then
        cp /var/adm/lastlog $OUTPUT_DIR/user_activity/lastlog.raw 2> /dev/null
        lastlog 1> $OUTPUT_DIR/user_activity/lastlog.txt 2> /dev/null
    fi
    if [ -f /var/adm/utmpx ]; then
        cp /var/adm/utmpx $OUTPUT_DIR/user_activity/utmpx.raw 2> /dev/null
        who -a /var/adm/utmpx 1> $OUTPUT_DIR/user_activity/who-utmpx.txt 2> /dev/null
    fi
    w 1> $OUTPUT_DIR/user_activity/w-current-users.txt 2> /dev/null
    who -a 1> $OUTPUT_DIR/user_activity/who-all.txt 2> /dev/null
elif [ $PLATFORM = "aix" ]
then
    # AIX login records
    if [ -f /var/adm/wtmp ]; then
        cp /var/adm/wtmp $OUTPUT_DIR/user_activity/wtmp.raw 2> /dev/null
        last -f /var/adm/wtmp 1> $OUTPUT_DIR/user_activity/last-wtmp.txt 2> /dev/null
    fi
    if [ -f /etc/security/lastlog ]; then
        cp /etc/security/lastlog $OUTPUT_DIR/user_activity/lastlog.raw 2> /dev/null
        lsuser -f ALL 1> $OUTPUT_DIR/user_activity/lsuser-all.txt 2> /dev/null
    fi
    w 1> $OUTPUT_DIR/user_activity/w-current-users.txt 2> /dev/null
    who -a 1> $OUTPUT_DIR/user_activity/who-all.txt 2> /dev/null
elif [ $PLATFORM = "mac" ]
then
    # macOS login records
    if [ -f /var/log/wtmp ]; then
        cp /var/log/wtmp $OUTPUT_DIR/user_activity/wtmp.raw 2> /dev/null
        last 1> $OUTPUT_DIR/user_activity/last.txt 2> /dev/null
    fi
    if [ -f /var/log/lastlog ]; then
        cp /var/log/lastlog $OUTPUT_DIR/user_activity/lastlog.raw 2> /dev/null
        lastlog 1> $OUTPUT_DIR/user_activity/lastlog.txt 2> /dev/null
    fi
    # macOS specific logs
    log show --predicate 'process == "loginwindow"' --last 7d 1> $OUTPUT_DIR/user_activity/loginwindow-7days.txt 2> /dev/null
    log show --predicate 'eventMessage contains "Authentication"' --last 7d 1> $OUTPUT_DIR/user_activity/authentication-7days.txt 2> /dev/null
    w 1> $OUTPUT_DIR/user_activity/w-current-users.txt 2> /dev/null
    who -a 1> $OUTPUT_DIR/user_activity/who-all.txt 2> /dev/null
    ac -p 1> $OUTPUT_DIR/user_activity/ac-user-connect-time.txt 2> /dev/null
elif [ $PLATFORM = "android" ]
then
    # Android doesn't have traditional login records
    dumpsys user 1> $OUTPUT_DIR/user_activity/android-user-state.txt 2> /dev/null
    dumpsys account 1> $OUTPUT_DIR/user_activity/android-accounts.txt 2> /dev/null
fi

# Collect SSH authentication logs
echo "    Collecting SSH authentication logs..."
mkdir $OUTPUT_DIR/user_activity/ssh_logs 2> /dev/null
if [ -f /var/log/auth.log ]; then
    grep -i ssh /var/log/auth.log 1> $OUTPUT_DIR/user_activity/ssh_logs/auth-ssh.txt 2> /dev/null
    grep -i "Accepted\|Failed\|Invalid" /var/log/auth.log 1> $OUTPUT_DIR/user_activity/ssh_logs/auth-login-attempts.txt 2> /dev/null
fi
if [ -f /var/log/secure ]; then
    grep -i ssh /var/log/secure 1> $OUTPUT_DIR/user_activity/ssh_logs/secure-ssh.txt 2> /dev/null
    grep -i "Accepted\|Failed\|Invalid" /var/log/secure 1> $OUTPUT_DIR/user_activity/ssh_logs/secure-login-attempts.txt 2> /dev/null
fi
if [ -f /var/log/messages ]; then
    grep -i "sshd\|authentication" /var/log/messages 1> $OUTPUT_DIR/user_activity/ssh_logs/messages-ssh.txt 2> /dev/null
fi
# Copy SSH host keys info
ls -la /etc/ssh/ssh_host_* 1> $OUTPUT_DIR/user_activity/ssh_logs/ssh_host_keys_list.txt 2> /dev/null

# Collect user shell history files
echo "    Collecting user shell history files..."
mkdir $OUTPUT_DIR/user_activity/shell_history 2> /dev/null
# Get list of users with valid shells
if [ -f /etc/passwd ]; then
    # Process each user
    cat /etc/passwd | while IFS=: read username x uid gid gecos homedir shell
    do
        # Skip system users and users without home directories
        if [ $uid -ge 500 -o $uid -eq 0 ] && [ -d "$homedir" ]; then
            user_history_dir="$OUTPUT_DIR/user_activity/shell_history/$username"
            mkdir $user_history_dir 2> /dev/null
            
            # Collect various shell history files
            for history_file in .bash_history .sh_history .zsh_history .ksh_history .history .ash_history .dash_history
            do
                if [ -f "$homedir/$history_file" ]; then
                    cp "$homedir/$history_file" "$user_history_dir/$history_file" 2> /dev/null
                    # Also create readable version
                    cat "$homedir/$history_file" 1> "$user_history_dir/${history_file}.txt" 2> /dev/null
                fi
            done
            
            # Collect shell configuration files that might contain history settings
            for config_file in .bashrc .bash_profile .profile .zshrc .kshrc
            do
                if [ -f "$homedir/$config_file" ]; then
                    grep -i "history\|HIST" "$homedir/$config_file" 1> "$user_history_dir/${config_file}_history_settings.txt" 2> /dev/null
                fi
            done
            
            # Collect recently used files
            if [ -d "$homedir/.local/share" ]; then
                find "$homedir/.local/share" -name "*recent*" -o -name "*history*" 2> /dev/null | head -20 | while read recent_file
                do
                    relative_path=`echo $recent_file | sed "s|$homedir/||"`
                    mkdir -p "$user_history_dir/`dirname $relative_path`" 2> /dev/null
                    cp "$recent_file" "$user_history_dir/$relative_path" 2> /dev/null
                done
            fi
            
            # Get last modified times for history files
            ls -la $homedir/.*history* 1> "$user_history_dir/history_files_list.txt" 2> /dev/null
        fi
    done
fi

# Collect sudo logs
echo "    Collecting sudo activity logs..."
mkdir $OUTPUT_DIR/user_activity/sudo_logs 2> /dev/null
if [ -f /var/log/sudo.log ]; then
    cp /var/log/sudo.log $OUTPUT_DIR/user_activity/sudo_logs/ 2> /dev/null
fi
if [ -f /var/log/auth.log ]; then
    grep -i sudo /var/log/auth.log 1> $OUTPUT_DIR/user_activity/sudo_logs/auth-sudo.txt 2> /dev/null
fi
if [ -f /var/log/secure ]; then
    grep -i sudo /var/log/secure 1> $OUTPUT_DIR/user_activity/sudo_logs/secure-sudo.txt 2> /dev/null
fi
# Sudo timestamp files
if [ -d /var/run/sudo ]; then
    ls -la /var/run/sudo/ 1> $OUTPUT_DIR/user_activity/sudo_logs/sudo_timestamps.txt 2> /dev/null
fi
if [ -d /var/db/sudo ]; then
    ls -la /var/db/sudo/ 1> $OUTPUT_DIR/user_activity/sudo_logs/sudo_db_timestamps.txt 2> /dev/null
fi

# Collect su logs
echo "    Collecting su activity logs..."
if [ -f /var/log/sulog ]; then
    cp /var/log/sulog $OUTPUT_DIR/user_activity/sulog 2> /dev/null
fi
if [ -f /var/adm/sulog ]; then
    cp /var/adm/sulog $OUTPUT_DIR/user_activity/sulog 2> /dev/null
fi

# Platform specific user activity
if [ $PLATFORM = "linux" ]; then
    # SystemD journal logs for user sessions
    if [ -x /usr/bin/journalctl ]; then
        journalctl _COMM=sshd --since "90 days ago" 1> $OUTPUT_DIR/user_activity/journalctl-sshd-90.txt 2> /dev/null
        journalctl _COMM=sudo --since "90 days ago" 1> $OUTPUT_DIR/user_activity/journalctl-sudo-90days.txt 2> /dev/null
        journalctl _COMM=su --since "90 days ago" 1> $OUTPUT_DIR/user_activity/journalctl-su-90days.txt 2> /dev/null
        loginctl list-sessions 1> $OUTPUT_DIR/user_activity/loginctl-sessions.txt 2> /dev/null
        loginctl list-users 1> $OUTPUT_DIR/user_activity/loginctl-users.txt 2> /dev/null
    fi
    # PAM logs
    if [ -d /var/log/pam ]; then
        cp -R /var/log/pam $OUTPUT_DIR/user_activity/ 2> /dev/null
    fi
elif [ $PLATFORM = "mac" ]; then
    # macOS specific user activity
    dscl . -list /Users | grep -v '^_' | while read username
    do
        echo "User: $username" 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
        dscl . -read /Users/$username LastLoginTime 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
        dscl . -read /Users/$username accountPolicyData 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
        echo "---" 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
    done
elif [ $PLATFORM = "solaris" ]; then
    # Solaris specific
    if [ -f /var/log/authlog ]; then
        cp /var/log/authlog $OUTPUT_DIR/user_activity/ 2> /dev/null
    fi
    logins -x 1> $OUTPUT_DIR/user_activity/logins-extended.txt 2> /dev/null
fi

# Create user activity summary
echo "=== User Activity Collection Summary ===" 1> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "Platform: $PLATFORM" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "Collection Date: `date`" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "Currently logged in users:" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
who | wc -l 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "User accounts with UID >= 500 or UID 0:" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
awk -F: '$3 >= 500 || $3 == 0 {print $1}' /etc/passwd 2> /dev/null | sort 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null

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

# File ACLs and extended attributes
echo "  ${COL_ENTRY}>${RESET} File ACLs and extended attributes"
if [ -x "$(command -v getfacl)" ]; then
    find / -xdev -type f -exec getfacl {} + > $OUTPUT_DIR/general/file_acls_getfacl.txt 2>/dev/null &
fi
if [ -x "$(command -v getfattr)" ]; then
    find / -xdev -type f -exec getfattr -d {} + > $OUTPUT_DIR/general/extended_file_attributes_getfattr.txt 2>/dev/null &
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
    
    # Package verification for Solaris
    echo "  ${COL_ENTRY}>${RESET} Verifying package integrity (Solaris)"
    mkdir $OUTPUT_DIR/software/verification 2> /dev/null
    pkg verify 1> $OUTPUT_DIR/software/verification/pkg-verify-all.txt 2> /dev/null
    pkg verify -v 1> $OUTPUT_DIR/software/verification/pkg-verify-verbose.txt 2> /dev/null
    pkg verify 2>&1 | grep -E "ERROR|FAIL" 1> $OUTPUT_DIR/software/verification/pkg-verify-errors.txt 2> /dev/null
    if [ -x /usr/bin/pkg ]; then
        pkg list 1> $OUTPUT_DIR/software/verification/ips-packages.txt 2> /dev/null
        for pkg in system/core-os system/kernel system/library
        do
            echo "=== Verifying $pkg ===" 1>> $OUTPUT_DIR/software/verification/critical-pkg-verify.txt 2> /dev/null
            pkg verify $pkg 1>> $OUTPUT_DIR/software/verification/critical-pkg-verify.txt 2> /dev/null
            echo "" 1>> $OUTPUT_DIR/software/verification/critical-pkg-verify.txt 2> /dev/null
        done
    fi
    
elif [ $PLATFORM = "aix" ]
then
    lslpp -L all 1> $OUTPUT_DIR/software/software-lslpp.txt 2> /dev/null
    lslpp -Lc 1> $OUTPUT_DIR/software/aix-patchlist.txt 2> /dev/null
    pkginfo 1> $OUTPUT_DIR/software/software-pkginfo.txt 2> /dev/null
    
    # Package verification for AIX
    echo "  ${COL_ENTRY}>${RESET} Verifying package integrity (AIX)"
    mkdir $OUTPUT_DIR/software/verification 2> /dev/null
    lppchk -v 1> $OUTPUT_DIR/software/verification/lppchk-verify.txt 2> /dev/null
    lppchk -c 1> $OUTPUT_DIR/software/verification/lppchk-checksum.txt 2> /dev/null
    lppchk -l 1> $OUTPUT_DIR/software/verification/lppchk-links.txt 2> /dev/null
    lppchk -n 1> $OUTPUT_DIR/software/verification/lppchk-requisites.txt 2> /dev/null
    lppchk -f 1> $OUTPUT_DIR/software/verification/lppchk-files.txt 2> /dev/null
    
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
    
    # Package verification for Android
    echo "  ${COL_ENTRY}>${RESET} Verifying package integrity (Android)"
    mkdir $OUTPUT_DIR/software/verification 2> /dev/null
    pm list packages | sed 's/package://' | while read pkg
    do
        echo "=== Package: $pkg ===" 1>> $OUTPUT_DIR/software/verification/package-signatures.txt 2> /dev/null
        dumpsys package $pkg | grep -A5 "signatures=" 1>> $OUTPUT_DIR/software/verification/package-signatures.txt 2> /dev/null
        echo "" 1>> $OUTPUT_DIR/software/verification/package-signatures.txt 2> /dev/null
    done
    
elif [ $PLATFORM = "mac" ]
then
    find / -iname "*.app" 1> $OUTPUT_DIR/software/software-apps.txt 2> /dev/null
    find / -iname "*.plist" 1> $OUTPUT_DIR/software/software-plist.txt 2> /dev/null
    ls -la /Applications/ 1> $OUTPUT_DIR/software/software-Applications-folder.txt 2> /dev/null
    mkdir $OUTPUT_DIR/software/System_Kernel_Extensions/ 2> /dev/null
    cp -R /System/Library/Extensions/ $OUTPUT_DIR/software/System_Kernel_Extensions/ 2> /dev/null
    mkdir $OUTPUT_DIR/software/Library_Kernel_Extensions/ 2> /dev/null
    cp -R /Library/Extensions/ $OUTPUT_DIR/software/Library_Kernel_Extensions/ 2> /dev/null
    
    # Package verification for macOS
    echo "  ${COL_ENTRY}>${RESET} Verifying package integrity (macOS)"
    mkdir $OUTPUT_DIR/software/verification 2> /dev/null
    if [ -x /usr/bin/csrutil ]; then
        csrutil status 1> $OUTPUT_DIR/software/verification/csrutil-status.txt 2> /dev/null
    fi
    find /Applications -maxdepth 2 -name "*.app" 2> /dev/null | head -50 | while read app
    do
        app_name=`basename "$app"`
        echo "=== $app_name ===" 1>> $OUTPUT_DIR/software/verification/app-signatures.txt 2> /dev/null
        codesign -vvv "$app" 1>> $OUTPUT_DIR/software/verification/app-signatures.txt 2>&1
        echo "" 1>> $OUTPUT_DIR/software/verification/app-signatures.txt 2> /dev/null
    done
    spctl --status 1> $OUTPUT_DIR/software/verification/gatekeeper-status.txt 2> /dev/null
    spctl --list 1> $OUTPUT_DIR/software/verification/notarized-apps.txt 2> /dev/null
    
elif [ $PLATFORM = "hpux" ]
then
    swlist 1> $OUTPUT_DIR/software/software-swlist.txt 2> /dev/null
    swlist -l fileset -a revision 1> $OUTPUT_DIR/software/hpux-patchlist.txt 2> /dev/null
    
    # Package verification for HP-UX
    echo "  ${COL_ENTRY}>${RESET} Verifying package integrity (HP-UX)"
    mkdir $OUTPUT_DIR/software/verification 2> /dev/null
    swverify -x autoselect_dependencies=false \* 1> $OUTPUT_DIR/software/verification/swverify-all.txt 2> /dev/null
    swverify -x check_permissions=true -x check_requisites=true \* 1> $OUTPUT_DIR/software/verification/swverify-detailed.txt 2> /dev/null
    
else
    # Linux and generic platforms
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
    chkconfig --list > $OUTPUT_DIR/software/chkconfig--list.txt 2> /dev/null
    pkg info > $OUTPUT_DIR/software/freebsd-patchlist_pkg_info.txt 2> /dev/null
    
    # Package verification for Linux
    echo "  ${COL_ENTRY}>${RESET} Verifying package integrity"
    mkdir $OUTPUT_DIR/software/verification 2> /dev/null
    
    # RPM-based verification
    if [ -x /usr/bin/rpm -o -x /bin/rpm ]; then
        echo "    Verifying RPM packages (this may take several minutes)..."
        rpm -Va 1> $OUTPUT_DIR/software/verification/rpm-verify-all.txt 2> /dev/null
        rpm -V --nofiles --nodigest -a 1> $OUTPUT_DIR/software/verification/rpm-verify-quick.txt 2> /dev/null
        rpm -Va 2> /dev/null | grep '^..5' 1> $OUTPUT_DIR/software/verification/rpm-modified-configs.txt 2> /dev/null
        rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\n' | grep -v 'Key ID' 1> $OUTPUT_DIR/software/verification/rpm-unsigned-packages.txt 2> /dev/null
        for pkg in kernel glibc systemd openssh openssl sudo pam
        do
            rpm -q $pkg > /dev/null 2>&1 && {
                echo "=== Verifying $pkg packages ===" 1>> $OUTPUT_DIR/software/verification/rpm-critical-packages.txt 2> /dev/null
                rpm -V $pkg* 1>> $OUTPUT_DIR/software/verification/rpm-critical-packages.txt 2> /dev/null
                echo "" 1>> $OUTPUT_DIR/software/verification/rpm-critical-packages.txt 2> /dev/null
            }
        done
    fi
    
    # Debian-based verification
    if [ -x /usr/bin/dpkg ]; then
        echo "    Verifying DEB packages (this may take several minutes)..."
        dpkg --verify 1> $OUTPUT_DIR/software/verification/dpkg-verify-all.txt 2> /dev/null
        if [ -x /usr/bin/debsums ]; then
            debsums -a 1> $OUTPUT_DIR/software/verification/debsums-all.txt 2> /dev/null
            debsums -c 1> $OUTPUT_DIR/software/verification/debsums-changed.txt 2> /dev/null
            debsums -l 1> $OUTPUT_DIR/software/verification/debsums-missing.txt 2> /dev/null
        fi
        apt-key list 1> $OUTPUT_DIR/software/verification/apt-keys.txt 2> /dev/null
        dpkg -l | grep '^ii' | awk '{print $2}' | while read pkg
        do
            apt-cache show $pkg 2> /dev/null | grep -q "^MD5sum:" || echo $pkg 1>> $OUTPUT_DIR/software/verification/dpkg-no-checksums.txt 2> /dev/null
        done
    fi
    
    # FreeBSD package verification
    if [ -x /usr/sbin/pkg ]; then
        echo "    Verifying FreeBSD packages..."
        pkg check -sa 1> $OUTPUT_DIR/software/verification/pkg-check-all.txt 2> /dev/null
        pkg check -d 1> $OUTPUT_DIR/software/verification/pkg-check-dependencies.txt 2> /dev/null
        pkg check -s 1> $OUTPUT_DIR/software/verification/pkg-check-checksums.txt 2> /dev/null
    fi
    
    # OpenBSD package verification
    if [ -x /usr/sbin/pkg_check ]; then
        echo "    Verifying OpenBSD packages..."
        pkg_check 1> $OUTPUT_DIR/software/verification/pkg_check.txt 2> /dev/null
        pkg_check -F 1> $OUTPUT_DIR/software/verification/pkg_check-files.txt 2> /dev/null
    fi
    
    # Snap package verification
    if [ -x /usr/bin/snap ]; then
        echo "    Checking snap packages..."
        snap list 1> $OUTPUT_DIR/software/verification/snap-list.txt 2> /dev/null
        snap changes 1> $OUTPUT_DIR/software/verification/snap-changes.txt 2> /dev/null
    fi
    
    # Flatpak verification
    if [ -x /usr/bin/flatpak ]; then
        echo "    Checking flatpak packages..."
        flatpak list 1> $OUTPUT_DIR/software/verification/flatpak-list.txt 2> /dev/null
        flatpak remotes 1> $OUTPUT_DIR/software/verification/flatpak-remotes.txt 2> /dev/null
    fi
fi

# Create package verification summary
echo "  ${COL_ENTRY}>${RESET} Creating verification summary"
echo "=== Package Verification Summary ===" 1> $OUTPUT_DIR/software/verification/summary.txt 2> /dev/null
echo "Platform: $PLATFORM" 1>> $OUTPUT_DIR/software/verification/summary.txt 2> /dev/null
echo "Verification Date: `date`" 1>> $OUTPUT_DIR/software/verification/summary.txt 2> /dev/null
echo "" 1>> $OUTPUT_DIR/software/verification/summary.txt 2> /dev/null

# Count verification issues if files exist
if [ -f $OUTPUT_DIR/software/verification/rpm-verify-all.txt ]; then
    RPM_ISSUES=`grep -c '^..5' $OUTPUT_DIR/software/verification/rpm-verify-all.txt 2> /dev/null || echo 0`
    echo "RPM verification issues: $RPM_ISSUES" 1>> $OUTPUT_DIR/software/verification/summary.txt 2> /dev/null
fi
if [ -f $OUTPUT_DIR/software/verification/debsums-changed.txt ]; then
    DEB_ISSUES=`wc -l < $OUTPUT_DIR/software/verification/debsums-changed.txt 2> /dev/null || echo 0`
    echo "DEB verification issues: $DEB_ISSUES" 1>> $OUTPUT_DIR/software/verification/summary.txt 2> /dev/null
fi
if [ -f $OUTPUT_DIR/software/verification/pkg-verify-errors.txt ]; then
    SOLARIS_ISSUES=`wc -l < $OUTPUT_DIR/software/verification/pkg-verify-errors.txt 2> /dev/null || echo 0`
    echo "Solaris pkg verification errors: $SOLARIS_ISSUES" 1>> $OUTPUT_DIR/software/verification/summary.txt 2> /dev/null
fi
if [ -f $OUTPUT_DIR/software/verification/lppchk-verify.txt ]; then
    AIX_ISSUES=`grep -c "PROBLEMS" $OUTPUT_DIR/software/verification/lppchk-verify.txt 2> /dev/null || echo 0`
    echo "AIX lppchk issues: $AIX_ISSUES" 1>> $OUTPUT_DIR/software/verification/summary.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Installed patches and update history"
mkdir $OUTPUT_DIR/software/patches 2> /dev/null

if [ $PLATFORM = "solaris" ]
then
    showrev -p 1> $OUTPUT_DIR/software/patches/showrev-p.txt 2> /dev/null
    patchadd -p 1> $OUTPUT_DIR/software/patches/patchadd-p.txt 2> /dev/null
    # Solaris 11+ uses pkg for patches
    if [ -x /usr/bin/pkg ]; then
        pkg history 1> $OUTPUT_DIR/software/patches/pkg-history.txt 2> /dev/null
        pkg history -l 1> $OUTPUT_DIR/software/patches/pkg-history-long.txt 2> /dev/null
        pkg list -Hv entire 1> $OUTPUT_DIR/software/patches/pkg-entire-incorporation.txt 2> /dev/null
    fi
    # Check patch logs
    if [ -d /var/sadm/patch ]; then
        ls -la /var/sadm/patch/ 1> $OUTPUT_DIR/software/patches/patch-directory.txt 2> /dev/null
    fi
    
elif [ $PLATFORM = "mac" ]
then
    system_profiler SPInstallHistoryDataType 1> $OUTPUT_DIR/software/patches/SPInstallHistoryDataType.txt 2> /dev/null
    softwareupdate --history --all 1> $OUTPUT_DIR/software/patches/softwareupdate-history.txt 2> /dev/null
    cp /Library/Receipts/InstallHistory.plist $OUTPUT_DIR/software/patches/ 2> /dev/null
    # Additional macOS update logs
    if [ -d /var/log/install.log ]; then
        cp /var/log/install.log $OUTPUT_DIR/software/patches/ 2> /dev/null
    fi
    # List available updates
    softwareupdate -l 1> $OUTPUT_DIR/software/patches/available-updates.txt 2> /dev/null
    
elif [ $PLATFORM = "aix" ]
then
    instfix -a 1> $OUTPUT_DIR/software/patches/instfix-all.txt 2> /dev/null
    instfix -i 1> $OUTPUT_DIR/software/patches/instfix-installed.txt 2> /dev/null
    # List all fixes with dates
    instfix -icqk 1> $OUTPUT_DIR/software/patches/instfix-detailed.txt 2> /dev/null
    # Check for specific APAR fixes
    instfix -ik APAR 1> $OUTPUT_DIR/software/patches/apar-fixes.txt 2> /dev/null
    # Service pack info
    oslevel -s 1> $OUTPUT_DIR/software/patches/service-pack.txt 2> /dev/null
    oslevel -sq 1> $OUTPUT_DIR/software/patches/service-pack-history.txt 2> /dev/null
    
elif [ $PLATFORM = "hpux" ]
then
    # HP-UX patch information
    swlist -l patch 1> $OUTPUT_DIR/software/patches/swlist-patches.txt 2> /dev/null
    swlist -l bundle 1> $OUTPUT_DIR/software/patches/swlist-bundles.txt 2> /dev/null
    # Show patch details
    swlist -a patch_state 1> $OUTPUT_DIR/software/patches/patch-states.txt 2> /dev/null
    # Check for patch bundles
    swlist -l bundle -a readme 1> $OUTPUT_DIR/software/patches/bundle-readme.txt 2> /dev/null
    
elif [ $PLATFORM = "android" ]
then
    # Android system updates are different
    getprop ro.build.version.security_patch 1> $OUTPUT_DIR/software/patches/security-patch-level.txt 2> /dev/null
    getprop ro.build.version.release 1> $OUTPUT_DIR/software/patches/android-version.txt 2> /dev/null
    getprop ro.build.date 1> $OUTPUT_DIR/software/patches/build-date.txt 2> /dev/null
    # OTA update logs if available
    if [ -f /cache/recovery/last_log ]; then
        cp /cache/recovery/last_log $OUTPUT_DIR/software/patches/last-ota-log.txt 2> /dev/null
    fi
    
elif [ $PLATFORM = "linux" -o $PLATFORM = "generic" ]
then
    # RPM-based systems (Red Hat, CentOS, SUSE, etc.)
    if [ -x /usr/bin/yum ]; then
        echo "    Collecting YUM patch history..."
        yum history 1> $OUTPUT_DIR/software/patches/yum-history.txt 2> /dev/null
        yum history list all 1> $OUTPUT_DIR/software/patches/yum-history-all.txt 2> /dev/null
        # Get detailed info for recent transactions
        yum history list | head -20 | grep -E '^[[:space:]]*[0-9]+' | awk '{print $1}' | while read trans_id
        do
            echo "=== Transaction $trans_id ===" 1>> $OUTPUT_DIR/software/patches/yum-history-details.txt 2> /dev/null
            yum history info $trans_id 1>> $OUTPUT_DIR/software/patches/yum-history-details.txt 2> /dev/null
            echo "" 1>> $OUTPUT_DIR/software/patches/yum-history-details.txt 2> /dev/null
        done
        # List available updates
        yum check-update 1> $OUTPUT_DIR/software/patches/yum-available-updates.txt 2> /dev/null
        # Security updates
        yum list-security 1> $OUTPUT_DIR/software/patches/yum-security-updates.txt 2> /dev/null
    fi
    
    # DNF (Fedora, newer Red Hat)
    if [ -x /usr/bin/dnf ]; then
        echo "    Collecting DNF patch history..."
        dnf history 1> $OUTPUT_DIR/software/patches/dnf-history.txt 2> /dev/null
        dnf history list all 1> $OUTPUT_DIR/software/patches/dnf-history-all.txt 2> /dev/null
        # List available updates
        dnf check-update 1> $OUTPUT_DIR/software/patches/dnf-available-updates.txt 2> /dev/null
        # Security updates
        dnf updateinfo list security 1> $OUTPUT_DIR/software/patches/dnf-security-updates.txt 2> /dev/null
    fi
    
    # Zypper (SUSE, openSUSE)
    if [ -x /usr/bin/zypper ]; then
        echo "    Collecting Zypper patch history..."
        zypper patches 1> $OUTPUT_DIR/software/patches/zypper-patches.txt 2> /dev/null
        zypper list-patches 1> $OUTPUT_DIR/software/patches/zypper-list-patches.txt 2> /dev/null
        # Patch history
        if [ -f /var/log/zypp/history ]; then
            cp /var/log/zypp/history $OUTPUT_DIR/software/patches/zypper-history.txt 2> /dev/null
        fi
        # Available updates
        zypper list-updates 1> $OUTPUT_DIR/software/patches/zypper-available-updates.txt 2> /dev/null
    fi
    
    # APT-based systems (Debian, Ubuntu, etc.)
    if [ -x /usr/bin/apt -o -x /usr/bin/apt-get ]; then
        echo "    Collecting APT patch history..."
        # APT history logs
        if [ -f /var/log/apt/history.log ]; then
            cp /var/log/apt/history.log $OUTPUT_DIR/software/patches/apt-history.log 2> /dev/null
        fi
        if [ -f /var/log/apt/term.log ]; then
            cp /var/log/apt/term.log $OUTPUT_DIR/software/patches/apt-term.log 2> /dev/null
        fi
        # Rotated logs
        for aptlog in /var/log/apt/history.log.*
        do
            if [ -f "$aptlog" ]; then
                filename=`basename $aptlog`
                cp $aptlog $OUTPUT_DIR/software/patches/$filename 2> /dev/null
            fi
        done
        # dpkg log
        if [ -f /var/log/dpkg.log ]; then
            cp /var/log/dpkg.log $OUTPUT_DIR/software/patches/ 2> /dev/null
        fi
        # List available updates
        apt list --upgradable 1> $OUTPUT_DIR/software/patches/apt-upgradable.txt 2> /dev/null
        # Update package info
        if [ -f /var/lib/apt/periodic/update-success-stamp ]; then
            ls -la /var/lib/apt/periodic/update-success-stamp 1> $OUTPUT_DIR/software/patches/apt-last-update.txt 2> /dev/null
        fi
        # Unattended upgrades log
        if [ -f /var/log/unattended-upgrades/unattended-upgrades.log ]; then
            cp /var/log/unattended-upgrades/unattended-upgrades.log $OUTPUT_DIR/software/patches/ 2> /dev/null
        fi
    fi
    
    # Emerge (Gentoo)
    if [ -x /usr/bin/emerge ]; then
        echo "    Collecting Emerge patch history..."
        if [ -f /var/log/emerge.log ]; then
            tail -1000 /var/log/emerge.log 1> $OUTPUT_DIR/software/patches/emerge-recent.log 2> /dev/null
        fi
        # Security patches
        glsa-check -l 1> $OUTPUT_DIR/software/patches/glsa-security-patches.txt 2> /dev/null
    fi
    
    # Pacman (Arch Linux)
    if [ -x /usr/bin/pacman ]; then
        echo "    Collecting Pacman patch history..."
        if [ -f /var/log/pacman.log ]; then
            cp /var/log/pacman.log $OUTPUT_DIR/software/patches/ 2> /dev/null
        fi
        # List outdated packages
        pacman -Qu 1> $OUTPUT_DIR/software/patches/pacman-outdated.txt 2> /dev/null
    fi
    
    # FreeBSD
    if [ -x /usr/sbin/freebsd-update ]; then
        echo "    Collecting FreeBSD update history..."
        freebsd-update fetch 1> $OUTPUT_DIR/software/patches/freebsd-update-check.txt 2> /dev/null
        # Check installed patches
        if [ -f /var/db/freebsd-update/tag ]; then
            cat /var/db/freebsd-update/tag 1> $OUTPUT_DIR/software/patches/freebsd-update-tag.txt 2> /dev/null
        fi
        # pkg updating shows available updates
        pkg updating 1> $OUTPUT_DIR/software/patches/pkg-updating.txt 2> /dev/null
    fi
    
    # OpenBSD
    if [ -x /usr/sbin/syspatch ]; then
        echo "    Collecting OpenBSD patch history..."
        syspatch -l 1> $OUTPUT_DIR/software/patches/syspatch-list.txt 2> /dev/null
        syspatch -c 1> $OUTPUT_DIR/software/patches/syspatch-check.txt 2> /dev/null
    fi
    
    # Check common update logs
    if [ -f /var/log/yum.log ]; then
        cp /var/log/yum.log $OUTPUT_DIR/software/patches/ 2> /dev/null
    fi
    if [ -f /var/log/dnf.log ]; then
        cp /var/log/dnf.log $OUTPUT_DIR/software/patches/ 2> /dev/null
    fi
    
    # Kernel update history
    if [ -d /boot ]; then
        ls -la /boot/vmlinuz* 1> $OUTPUT_DIR/software/patches/kernel-versions.txt 2> /dev/null
        ls -la /boot/initrd* 1>> $OUTPUT_DIR/software/patches/kernel-versions.txt 2> /dev/null
    fi
    
    # Check for automatic update configurations
    if [ -f /etc/yum/yum-cron.conf ]; then
        cp /etc/yum/yum-cron.conf $OUTPUT_DIR/software/patches/ 2> /dev/null
    fi
    if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
        cp /etc/apt/apt.conf.d/50unattended-upgrades $OUTPUT_DIR/software/patches/ 2> /dev/null
    fi
fi

echo "  ${COL_ENTRY}>${RESET} Compiler and development tools detection"
mkdir $OUTPUT_DIR/software/development_tools 2> /dev/null

# First, check common locations and PATH for known compilers/interpreters
echo "    Checking PATH for development tools..."
echo "=== Development Tools Found in PATH ===" > $OUTPUT_DIR/software/development_tools/tools_in_path.txt

# List of common development tools to check
DEV_TOOLS="gcc g++ cc c++ clang clang++ icc icpc pgcc xlc xlC javac java python python2 python3 perl perl5 ruby irb php node nodejs npm go gccgo rustc cargo swift swiftc kotlin kotlinc scala scalac ghc ocaml fpc gfortran f77 f90 f95 nasm yasm tclsh wish lua R julia dart mono mcs dotnet make gmake cmake qmake automake ant maven gradle rake pip pip3 gem npm yarn composer"

for tool in $DEV_TOOLS
do
    if command -v $tool > /dev/null 2>&1; then
        tool_path=`command -v $tool 2>/dev/null`
        echo "" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
        echo "=== $tool ===" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
        echo "Path: $tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
        ls -la "$tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt 2>/dev/null
        
        # Get version info if possible
        echo "Version:" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
        case $tool in
            gcc|g++|clang|clang++|gfortran)
                $tool --version 2>/dev/null | head -1 >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
                ;;
            javac|java)
                $tool -version 2>&1 | head -1 >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
                ;;
            python*|perl*|ruby|php|node|nodejs)
                $tool --version 2>&1 | head -1 >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
                ;;
            go|rustc|swift|kotlin*|scala*)
                $tool version 2>&1 | head -1 >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
                ;;
            *)
                $tool --version 2>&1 | head -1 >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt || echo "Version unknown" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
                ;;
        esac
        
        # Get file hash
        if [ -x /usr/bin/sha256sum ]; then
            sha256sum "$tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt 2>/dev/null
        elif [ -x /usr/bin/sha1sum ]; then
            sha1sum "$tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt 2>/dev/null
        elif [ -x /usr/bin/shasum ]; then
            shasum -a 256 "$tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt 2>/dev/null
        fi
    fi
done

# Check package manager for installed development packages
echo "    Checking installed development packages..."

if [ $PLATFORM = "linux" -o $PLATFORM = "generic" ]; then
    # RPM-based systems
    if [ -x /usr/bin/rpm -o -x /bin/rpm ]; then
        echo "=== RPM Development Packages ===" > $OUTPUT_DIR/software/development_tools/rpm_dev_packages.txt
        rpm -qa | grep -E 'gcc|clang|java|jdk|python|perl|ruby|nodejs|golang|rust|compiler|devel|sdk' | sort >> $OUTPUT_DIR/software/development_tools/rpm_dev_packages.txt 2>/dev/null
    fi
    
    # Debian-based systems
    if [ -x /usr/bin/dpkg ]; then
        echo "=== DEB Development Packages ===" > $OUTPUT_DIR/software/development_tools/deb_dev_packages.txt
        dpkg -l | grep -E 'gcc|clang|java|jdk|python|perl|ruby|nodejs|golang|rust|compiler|dev|sdk' | grep '^ii' >> $OUTPUT_DIR/software/development_tools/deb_dev_packages.txt 2>/dev/null
    fi
elif [ $PLATFORM = "mac" ]; then
    # Check Xcode and command line tools
    echo "=== Xcode Information ===" > $OUTPUT_DIR/software/development_tools/xcode_info.txt
    xcode-select -p >> $OUTPUT_DIR/software/development_tools/xcode_info.txt 2>&1
    xcodebuild -version >> $OUTPUT_DIR/software/development_tools/xcode_info.txt 2>&1
    pkgutil --pkg-info=com.apple.pkg.CLTools_Executables >> $OUTPUT_DIR/software/development_tools/xcode_info.txt 2>&1
    
    # Check Homebrew packages
    if [ -x /usr/local/bin/brew -o -x /opt/homebrew/bin/brew ]; then
        echo "=== Homebrew Development Packages ===" > $OUTPUT_DIR/software/development_tools/brew_dev_packages.txt
        brew list | grep -E 'gcc|llvm|java|python|perl|ruby|node|go|rust' >> $OUTPUT_DIR/software/development_tools/brew_dev_packages.txt 2>/dev/null
    fi
elif [ $PLATFORM = "solaris" ]; then
    if [ -x /usr/bin/pkg ]; then
        echo "=== Solaris Development Packages ===" > $OUTPUT_DIR/software/development_tools/solaris_dev_packages.txt
        pkg list | grep -E 'gcc|java|jdk|python|perl|ruby|developer|compiler' >> $OUTPUT_DIR/software/development_tools/solaris_dev_packages.txt 2>/dev/null
    fi
fi

# Check standard development directories
echo "    Checking standard development directories..."
echo "=== Development Tools in Standard Locations ===" > $OUTPUT_DIR/software/development_tools/standard_locations.txt

# Common directories to check (much faster than full filesystem scan)
DEV_DIRS="/usr/bin /usr/local/bin /opt/*/bin /usr/lib/jvm/*/bin /usr/lib64/jvm/*/bin /opt/rh/*/root/usr/bin /usr/local/go/bin /usr/local/rust/bin /usr/local/node*/bin /Applications/Xcode.app/Contents/Developer/usr/bin /Developer/usr/bin"

for dir in $DEV_DIRS
do
    if [ -d "$dir" ]; then
        echo "" >> $OUTPUT_DIR/software/development_tools/standard_locations.txt
        echo "=== Directory: $dir ===" >> $OUTPUT_DIR/software/development_tools/standard_locations.txt
        ls -la $dir 2>/dev/null | grep -E 'gcc|g\+\+|clang|javac|java|python|perl|ruby|node|go|rustc|swift' >> $OUTPUT_DIR/software/development_tools/standard_locations.txt 2>/dev/null
    fi
done

# Check for development environments and build tools
echo "    Checking build environments..."
echo "=== Build Tools and Environments ===" > $OUTPUT_DIR/software/development_tools/build_environments.txt

# Check for build tool configurations
for config in /etc/alternatives/java* /etc/alternatives/python* /etc/alternatives/gcc* /usr/lib/jvm/default-java /etc/java* /etc/python* /etc/perl* /etc/ruby*
do
    if [ -e "$config" ]; then
        echo "" >> $OUTPUT_DIR/software/development_tools/build_environments.txt
        echo "Config: $config" >> $OUTPUT_DIR/software/development_tools/build_environments.txt
        ls -la "$config" >> $OUTPUT_DIR/software/development_tools/build_environments.txt 2>/dev/null
    fi
done

# Check environment variables
echo "" >> $OUTPUT_DIR/software/development_tools/build_environments.txt
echo "=== Development Environment Variables ===" >> $OUTPUT_DIR/software/development_tools/build_environments.txt
env | grep -E 'JAVA_HOME|PYTHON_HOME|PERL5LIB|RUBY|GCC|GOPATH|GOROOT|CARGO_HOME|NODE_PATH|PATH' | sort >> $OUTPUT_DIR/software/development_tools/build_environments.txt 2>/dev/null

# Platform specific checks
if [ $PLATFORM = "android" ]; then
    echo "    Checking Android development tools..."
    echo "=== Android Development Tools ===" > $OUTPUT_DIR/software/development_tools/android_dev_tools.txt
    
    # Check for Android SDK/NDK
    find /opt /usr/local -name "android-sdk*" -o -name "android-ndk*" 2>/dev/null | head -20 >> $OUTPUT_DIR/software/development_tools/android_dev_tools.txt
    
    # Check dalvikvm
    if command -v dalvikvm > /dev/null 2>&1; then
        dalvikvm -version >> $OUTPUT_DIR/software/development_tools/android_dev_tools.txt 2>&1
    fi
fi
echo "    Performing targeted filesystem scan..."
echo "=== Compilers Found in Non-Standard Locations ===" > $OUTPUT_DIR/software/development_tools/nonstandard_compilers.txt

SEARCH_DIRS="/opt /usr/local /home /root"
for search_dir in $SEARCH_DIRS
do
    if [ -d "$search_dir" ]; then
        find $search_dir -maxdepth 4 -type f \( -name 'gcc' -o -name 'g++' -o -name 'clang' -o -name 'javac' -o -name 'python' -o -name 'python[23]' -o -name 'perl' -o -name 'ruby' -o -name 'go' -o -name 'rustc' -o -name 'node' \) -executable 2>/dev/null | head -50 | while read compiler
        do
            echo "" >> $OUTPUT_DIR/software/development_tools/nonstandard_compilers.txt
            echo "Found: $compiler" >> $OUTPUT_DIR/software/development_tools/nonstandard_compilers.txt
            ls -la "$compiler" >> $OUTPUT_DIR/software/development_tools/nonstandard_compilers.txt 2>/dev/null
        done
    fi
done

echo "    Creating development tools summary..."
echo "=== Development Tools Summary ===" > $OUTPUT_DIR/software/development_tools/summary.txt
echo "Platform: $PLATFORM" >> $OUTPUT_DIR/software/development_tools/summary.txt
echo "Collection Date: `date`" >> $OUTPUT_DIR/software/development_tools/summary.txt
echo "" >> $OUTPUT_DIR/software/development_tools/summary.txt

# Legacy compatibility - create the original simple list
echo "  ${COL_ENTRY}>${RESET} Creating legacy compiler list (NFS skip)"
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

echo "  ${COL_ENTRY}>${RESET} Network services configuration"
mkdir $OUTPUT_DIR/network/services 2> /dev/null

# Collect xinetd configuration
echo "    Collecting xinetd configuration..."
if [ -f /etc/xinetd.conf ]; then
    cp /etc/xinetd.conf $OUTPUT_DIR/network/services/ 2> /dev/null
    # Get xinetd status
    if command -v xinetd > /dev/null 2>&1; then
        xinetd -version 1> $OUTPUT_DIR/network/services/xinetd-version.txt 2>&1
    fi
fi
if [ -d /etc/xinetd.d ]; then
    mkdir $OUTPUT_DIR/network/services/xinetd.d 2> /dev/null
    cp -R /etc/xinetd.d/* $OUTPUT_DIR/network/services/xinetd.d/ 2> /dev/null
    # List enabled services
    echo "=== Enabled xinetd Services ===" > $OUTPUT_DIR/network/services/xinetd-enabled-services.txt
    grep -l "disable.*=.*no" /etc/xinetd.d/* 2>/dev/null | while read service_file
    do
        echo "Service: `basename $service_file`" >> $OUTPUT_DIR/network/services/xinetd-enabled-services.txt
        grep -E "server|port|socket_type|protocol" $service_file >> $OUTPUT_DIR/network/services/xinetd-enabled-services.txt 2>/dev/null
        echo "" >> $OUTPUT_DIR/network/services/xinetd-enabled-services.txt
    done
fi

# Collect inetd configuration
echo "    Collecting inetd configuration..."
if [ -f /etc/inetd.conf ]; then
    cp /etc/inetd.conf $OUTPUT_DIR/network/services/ 2> /dev/null
    # Extract active services (non-commented lines)
    grep -v "^#" /etc/inetd.conf | grep -v "^$" > $OUTPUT_DIR/network/services/inetd-active-services.txt 2> /dev/null
fi
# Some systems use inetd.d directory
if [ -d /etc/inetd.d ]; then
    mkdir $OUTPUT_DIR/network/services/inetd.d 2> /dev/null
    cp -R /etc/inetd.d/* $OUTPUT_DIR/network/services/inetd.d/ 2> /dev/null
fi

# Platform-specific network services
if [ $PLATFORM = "solaris" ]
then
    echo "    Collecting Solaris network services..."
    # SMF services (Service Management Facility)
    svcs -a 1> $OUTPUT_DIR/network/services/svcs-all.txt 2> /dev/null
    svcs -p 1> $OUTPUT_DIR/network/services/svcs-processes.txt 2> /dev/null
    # List network-related services
    svcs | grep -E "network|rpc|nfs|ssh|telnet|ftp|http" > $OUTPUT_DIR/network/services/svcs-network.txt 2> /dev/null
    # Get detailed info for network services
    svcs -l network/ssh > $OUTPUT_DIR/network/services/svcs-ssh-detail.txt 2> /dev/null
    svcs -l network/telnet > $OUTPUT_DIR/network/services/svcs-telnet-detail.txt 2> /dev/null
    # Legacy services
    if [ -f /etc/inet/inetd.conf ]; then
        cp /etc/inet/inetd.conf $OUTPUT_DIR/network/services/inetd.conf.solaris 2> /dev/null
    fi
    # RPC services
    if [ -f /etc/rpc ]; then
        cp /etc/rpc $OUTPUT_DIR/network/services/ 2> /dev/null
    fi
    
elif [ $PLATFORM = "aix" ]
then
    echo "    Collecting AIX network services..."
    # AIX uses SRC (System Resource Controller)
    lssrc -a 1> $OUTPUT_DIR/network/services/lssrc-all.txt 2> /dev/null
    # List inetd subservices
    lssrc -ls inetd 1> $OUTPUT_DIR/network/services/lssrc-inetd.txt 2> /dev/null
    # Get inetd configuration
    if [ -f /etc/inetd.conf ]; then
        cp /etc/inetd.conf $OUTPUT_DIR/network/services/ 2> /dev/null
    fi
    # tcpip configuration
    if [ -f /etc/rc.tcpip ]; then
        cp /etc/rc.tcpip $OUTPUT_DIR/network/services/ 2> /dev/null
    fi
    # List active ports
    lssrc -a | grep active > $OUTPUT_DIR/network/services/active-services.txt 2> /dev/null
    
elif [ $PLATFORM = "hpux" ]
then
    echo "    Collecting HP-UX network services..."
    # HP-UX inetd
    if [ -f /etc/inetd.conf ]; then
        cp /etc/inetd.conf $OUTPUT_DIR/network/services/ 2> /dev/null
    fi
    if [ -f /etc/inetd.sec ]; then
        cp /etc/inetd.sec $OUTPUT_DIR/network/services/ 2> /dev/null
    fi
    # Check service status
    ps -ef | grep -E "inetd|xinetd" | grep -v grep > $OUTPUT_DIR/network/services/inetd-processes.txt 2> /dev/null
    
elif [ $PLATFORM = "mac" ]
then
    echo "    Collecting macOS network services..."
    # launchd services (modern macOS)
    launchctl list 1> $OUTPUT_DIR/network/services/launchctl-list.txt 2> /dev/null
    # Network-specific launch daemons
    ls -la /System/Library/LaunchDaemons/ | grep -E "ssh|ftp|telnet|vnc|afp|smb" > $OUTPUT_DIR/network/services/network-daemons.txt 2> /dev/null
    # Copy network-related plist files
    mkdir $OUTPUT_DIR/network/services/launch_daemons 2> /dev/null
    for plist in ssh ftp telnet vnc afp smb
    do
        if [ -f /System/Library/LaunchDaemons/com.apple.*${plist}*.plist ]; then
            cp /System/Library/LaunchDaemons/com.apple.*${plist}*.plist $OUTPUT_DIR/network/services/launch_daemons/ 2> /dev/null
        fi
    done
    # Legacy xinetd if present
    if [ -f /etc/xinetd.conf ]; then
        cp /etc/xinetd.conf $OUTPUT_DIR/network/services/ 2> /dev/null
    fi
    # Sharing preferences
    if [ -f /Library/Preferences/SystemConfiguration/com.apple.nat.plist ]; then
        cp /Library/Preferences/SystemConfiguration/com.apple.nat.plist $OUTPUT_DIR/network/services/ 2> /dev/null
    fi
    
elif [ $PLATFORM = "android" ]
then
    echo "    Collecting Android network services..."
    # Android doesn't use traditional inetd/xinetd
    # List running services
    dumpsys connectivity 1> $OUTPUT_DIR/network/services/android-connectivity.txt 2> /dev/null
    # Get network service properties
    getprop | grep -E "net\.|dhcp\.|wifi\." > $OUTPUT_DIR/network/services/android-network-props.txt 2> /dev/null
    # List network-related services
    service list | grep -E "network|wifi|connectivity|netd" > $OUTPUT_DIR/network/services/android-network-services.txt 2> /dev/null
    
else
    # Linux and generic Unix systems
    echo "    Collecting Linux/Unix network services..."
    
    # SystemD socket activation (modern replacement for inetd)
    if command -v systemctl > /dev/null 2>&1; then
        echo "    Collecting systemd socket units..."
        systemctl list-unit-files --type=socket 1> $OUTPUT_DIR/network/services/systemd-sockets.txt 2> /dev/null
        systemctl list-units --type=socket --all 1> $OUTPUT_DIR/network/services/systemd-sockets-status.txt 2> /dev/null
        # Get details for active sockets
        mkdir $OUTPUT_DIR/network/services/systemd_socket_details 2> /dev/null
        systemctl list-units --type=socket --state=active --no-legend | awk '{print $1}' | while read socket_unit
        do
            systemctl show "$socket_unit" > $OUTPUT_DIR/network/services/systemd_socket_details/${socket_unit}.txt 2> /dev/null
        done
    fi
    
    # Traditional SysV init scripts
    if [ -d /etc/init.d ]; then
        ls -la /etc/init.d/ | grep -E "xinetd|inetd|portmap|rpc" > $OUTPUT_DIR/network/services/init.d-network-services.txt 2> /dev/null
    fi
    
    # Check for standalone network services
    for service in vsftpd proftpd sshd telnetd rpcbind nfs-server smbd nmbd httpd nginx
    do
        if [ -f /etc/init.d/$service ]; then
            cp /etc/init.d/$service $OUTPUT_DIR/network/services/init.d-$service 2> /dev/null
        fi
        if [ -f /etc/default/$service ]; then
            cp /etc/default/$service $OUTPUT_DIR/network/services/default-$service 2> /dev/null
        fi
        if [ -f /etc/sysconfig/$service ]; then
            cp /etc/sysconfig/$service $OUTPUT_DIR/network/services/sysconfig-$service 2> /dev/null
        fi
    done
fi

# Common network service configurations across platforms
echo "    Collecting common network service configurations..."

# RPC services
if [ -f /etc/rpc ]; then
    cp /etc/rpc $OUTPUT_DIR/network/services/ 2> /dev/null
fi

# Services database
if [ -f /etc/services ]; then
    cp /etc/services $OUTPUT_DIR/network/services/ 2> /dev/null
fi

# Portmap/rpcbind configuration
if [ -f /etc/default/portmap ]; then
    cp /etc/default/portmap $OUTPUT_DIR/network/services/ 2> /dev/null
fi
if [ -f /etc/default/rpcbind ]; then
    cp /etc/default/rpcbind $OUTPUT_DIR/network/services/ 2> /dev/null
fi

# NFS exports
if [ -f /etc/exports ]; then
    cp /etc/exports $OUTPUT_DIR/network/services/ 2> /dev/null
fi

# Check for active network listeners
echo "    Identifying active network services..."
echo "=== Active Network Services ===" > $OUTPUT_DIR/network/services/active-listeners.txt

# Get listening services with process information
if command -v ss > /dev/null 2>&1; then
    ss -tlnp 2>/dev/null | grep LISTEN >> $OUTPUT_DIR/network/services/active-listeners.txt
    ss -ulnp 2>/dev/null >> $OUTPUT_DIR/network/services/active-listeners.txt
elif command -v netstat > /dev/null 2>&1; then
    netstat -tlnp 2>/dev/null | grep LISTEN >> $OUTPUT_DIR/network/services/active-listeners.txt
    netstat -ulnp 2>/dev/null >> $OUTPUT_DIR/network/services/active-listeners.txt
fi

# Check xinetd/inetd process status
echo "" >> $OUTPUT_DIR/network/services/active-listeners.txt
echo "=== Super-server Status ===" >> $OUTPUT_DIR/network/services/active-listeners.txt
ps aux | grep -E "[x]inetd|[i]netd" >> $OUTPUT_DIR/network/services/active-listeners.txt 2> /dev/null

# tcpwrappers configuration
echo "    Collecting TCP wrappers configuration..."
if [ -f /etc/hosts.allow ]; then
    cp /etc/hosts.allow $OUTPUT_DIR/network/services/ 2> /dev/null
fi
if [ -f /etc/hosts.deny ]; then
    cp /etc/hosts.deny $OUTPUT_DIR/network/services/ 2> /dev/null
fi

# Create services summary
echo "    Creating network services summary..."
echo "=== Network Services Configuration Summary ===" > $OUTPUT_DIR/network/services/summary.txt
echo "Platform: $PLATFORM" >> $OUTPUT_DIR/network/services/summary.txt
echo "Collection Date: `date`" >> $OUTPUT_DIR/network/services/summary.txt
echo "" >> $OUTPUT_DIR/network/services/summary.txt

# Check for xinetd
if [ -f /etc/xinetd.conf ] || [ -d /etc/xinetd.d ]; then
    echo "xinetd: Configured" >> $OUTPUT_DIR/network/services/summary.txt
    if [ -f $OUTPUT_DIR/network/services/xinetd-enabled-services.txt ]; then
        XINETD_COUNT=`grep "^Service:" $OUTPUT_DIR/network/services/xinetd-enabled-services.txt | wc -l`
        echo "xinetd enabled services: $XINETD_COUNT" >> $OUTPUT_DIR/network/services/summary.txt
    fi
else
    echo "xinetd: Not found" >> $OUTPUT_DIR/network/services/summary.txt
fi

# Check for inetd
if [ -f /etc/inetd.conf ]; then
    echo "inetd: Configured" >> $OUTPUT_DIR/network/services/summary.txt
    if [ -f $OUTPUT_DIR/network/services/inetd-active-services.txt ]; then
        INETD_COUNT=`wc -l < $OUTPUT_DIR/network/services/inetd-active-services.txt`
        echo "inetd active services: $INETD_COUNT" >> $OUTPUT_DIR/network/services/summary.txt
    fi
else
    echo "inetd: Not found" >> $OUTPUT_DIR/network/services/summary.txt
fi

# SystemD sockets
if [ -f $OUTPUT_DIR/network/services/systemd-sockets-status.txt ]; then
    SOCKET_COUNT=`grep -c "\.socket" $OUTPUT_DIR/network/services/systemd-sockets-status.txt 2>/dev/null || echo 0`
    echo "SystemD socket units: $SOCKET_COUNT" >> $OUTPUT_DIR/network/services/summary.txt
fi

# TCP Wrappers
if [ -f /etc/hosts.allow ] || [ -f /etc/hosts.deny ]; then
    echo "TCP Wrappers: Configured" >> $OUTPUT_DIR/network/services/summary.txt
else
    echo "TCP Wrappers: Not configured" >> $OUTPUT_DIR/network/services/summary.txt
fi

# ---------------------------
# PART 9: VIRTUAL SYSTEMS INFORMATION
# ---------------------------
if [ -x "$(command -v esxcli)" -o -x "$(command -v VBoxManage)" -o -x "$(command -v virsh)" -o -x "$(command -v vim-cmd)" -o -x "$(command -v vmctl)" -o -x "$(command -v qm)" ]
then
    echo "${COL_SECTION}VIRTUAL SYSTEMS INFORMATION [95% ]:${RESET}"
    mkdir $OUTPUT_DIR/virtual
	# VMware ESXi
	if [ -x "$(command -v esxcli)" ] || [ -x "$(command -v vim-cmd)" ] || [ -x "$(command -v vm-support)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting VMware ESXi information"
		mkdir -p $OUTPUT_DIR/virtual/esxi
		mkdir -p $OUTPUT_DIR/virtual/esxi/system
		mkdir -p $OUTPUT_DIR/virtual/esxi/hardware
		mkdir -p $OUTPUT_DIR/virtual/esxi/network
		mkdir -p $OUTPUT_DIR/virtual/esxi/network/vswitches
		mkdir -p $OUTPUT_DIR/virtual/esxi/network/portgroups
		mkdir -p $OUTPUT_DIR/virtual/esxi/network/nics
		mkdir -p $OUTPUT_DIR/virtual/esxi/storage
		mkdir -p $OUTPUT_DIR/virtual/esxi/storage/adapters
		mkdir -p $OUTPUT_DIR/virtual/esxi/storage/devices
		mkdir -p $OUTPUT_DIR/virtual/esxi/storage/datastores
		mkdir -p $OUTPUT_DIR/virtual/esxi/storage/iscsi
		mkdir -p $OUTPUT_DIR/virtual/esxi/storage/vsan
		mkdir -p $OUTPUT_DIR/virtual/esxi/vms
		mkdir -p $OUTPUT_DIR/virtual/esxi/security
		mkdir -p $OUTPUT_DIR/virtual/esxi/config
		mkdir -p $OUTPUT_DIR/virtual/esxi/services
		mkdir -p $OUTPUT_DIR/virtual/esxi/logs
		mkdir -p $OUTPUT_DIR/virtual/esxi/logs/var_log
		mkdir -p $OUTPUT_DIR/virtual/esxi/logs/scratch_log
		mkdir -p $OUTPUT_DIR/virtual/esxi/performance
		mkdir -p $OUTPUT_DIR/virtual/esxi/cluster
		mkdir -p $OUTPUT_DIR/virtual/esxi/software
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi system information"
		esxcli system version get 1> $OUTPUT_DIR/virtual/esxi/system/version.txt 2> /dev/null
		vmware -vl 1> $OUTPUT_DIR/virtual/esxi/system/version_detailed.txt 2> /dev/null
		esxcli system hostname get 1> $OUTPUT_DIR/virtual/esxi/system/hostname.txt 2> /dev/null
		esxcli system stats installtime get 1> $OUTPUT_DIR/virtual/esxi/system/installtime.txt 2> /dev/null
		esxcli system time get 1> $OUTPUT_DIR/virtual/esxi/system/time.txt 2> /dev/null
		esxcli system ntp get 1> $OUTPUT_DIR/virtual/esxi/system/ntp_config.txt 2> /dev/null
		esxcli system maintenanceMode get 1> $OUTPUT_DIR/virtual/esxi/system/maintenance_mode.txt 2> /dev/null
		esxcli system uuid get 1> $OUTPUT_DIR/virtual/esxi/system/uuid.txt 2> /dev/null
		esxcli system welcomemsg get 1> $OUTPUT_DIR/virtual/esxi/system/welcome_message.txt 2> /dev/null
		esxcli system boot device get 1> $OUTPUT_DIR/virtual/esxi/system/boot_device.txt 2> /dev/null
		esxcli system visorfs ramdisk list 1> $OUTPUT_DIR/virtual/esxi/system/ramdisk_list.txt 2> /dev/null
		
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi hardware information"
		esxcli hardware platform get 1> $OUTPUT_DIR/virtual/esxi/hardware/platform.txt 2> /dev/null
		esxcli hardware cpu list 1> $OUTPUT_DIR/virtual/esxi/hardware/cpu_list.txt 2> /dev/null
		esxcli hardware cpu global get 1> $OUTPUT_DIR/virtual/esxi/hardware/cpu_global.txt 2> /dev/null
		esxcli hardware memory get 1> $OUTPUT_DIR/virtual/esxi/hardware/memory.txt 2> /dev/null
		esxcli hardware pci list 1> $OUTPUT_DIR/virtual/esxi/hardware/pci_devices.txt 2> /dev/null
		esxcli hardware clock get 1> $OUTPUT_DIR/virtual/esxi/hardware/clock.txt 2> /dev/null
		esxcli hardware bootdevice list 1> $OUTPUT_DIR/virtual/esxi/hardware/bootdevice.txt 2> /dev/null
		esxcli hardware trustedboot get 1> $OUTPUT_DIR/virtual/esxi/hardware/trustedboot.txt 2> /dev/null
		esxcli hardware usb passthrough device list 1> $OUTPUT_DIR/virtual/esxi/hardware/usb_passthrough.txt 2> /dev/null
		esxcli hardware power policy list 1> $OUTPUT_DIR/virtual/esxi/hardware/power_policies.txt 2> /dev/null
		esxcli hardware power policy get 1> $OUTPUT_DIR/virtual/esxi/hardware/current_power_policy.txt 2> /dev/null
		esxcli hardware ipmi sdr list 1> $OUTPUT_DIR/virtual/esxi/hardware/ipmi_sensors.txt 2> /dev/null
		esxcli hardware ipmi bmc get 1> $OUTPUT_DIR/virtual/esxi/hardware/ipmi_bmc.txt 2> /dev/null
		vmkchdev -l 1> $OUTPUT_DIR/virtual/esxi/hardware/vmkchdev_list.txt 2> /dev/null
	
		if [ -x "$(command -v vim-cmd)" ]; then
			vim-cmd hostsvc/hosthardware > $OUTPUT_DIR/virtual/esxi/hardware/host_hardware_detailed.txt 2> /dev/null
			vim-cmd hostsvc/hostsummary > $OUTPUT_DIR/virtual/esxi/hardware/host_summary.txt 2> /dev/null
		fi
		
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi network configuration"

		esxcli network ip interface list 1> $OUTPUT_DIR/virtual/esxi/network/ip_interfaces.txt 2> /dev/null
		esxcli network ip interface ipv4 get 1> $OUTPUT_DIR/virtual/esxi/network/ipv4_config.txt 2> /dev/null
		esxcli network ip interface ipv6 get 1> $OUTPUT_DIR/virtual/esxi/network/ipv6_config.txt 2> /dev/null
		esxcli network ip connection list 1> $OUTPUT_DIR/virtual/esxi/network/connections.txt 2> /dev/null
		esxcli network ip neighbor list 1> $OUTPUT_DIR/virtual/esxi/network/arp_table.txt 2> /dev/null
		esxcli network ip route ipv4 list 1> $OUTPUT_DIR/virtual/esxi/network/ipv4_routes.txt 2> /dev/null
		esxcli network ip route ipv6 list 1> $OUTPUT_DIR/virtual/esxi/network/ipv6_routes.txt 2> /dev/null
		esxcli network ip dns server list 1> $OUTPUT_DIR/virtual/esxi/network/dns_servers.txt 2> /dev/null
		esxcli network ip dns search list 1> $OUTPUT_DIR/virtual/esxi/network/dns_search.txt 2> /dev/null
		
		esxcli network nic list 1> $OUTPUT_DIR/virtual/esxi/network/nics/nic_list.txt 2> /dev/null
		esxcli network nic get -n vmnic0 1> $OUTPUT_DIR/virtual/esxi/network/nics/vmnic0_details.txt 2> /dev/null
		esxcli network nic stats get -n vmnic0 1> $OUTPUT_DIR/virtual/esxi/network/nics/vmnic0_stats.txt 2> /dev/null
	
		esxcli network nic list 2>/dev/null | grep -E "^vmnic" | awk '{print $1}' | while read nic; do
			[ -n "$nic" ] && {
				esxcli network nic get -n "$nic" > "$OUTPUT_DIR/virtual/esxi/network/nics/${nic}_details.txt" 2> /dev/null
				esxcli network nic stats get -n "$nic" > "$OUTPUT_DIR/virtual/esxi/network/nics/${nic}_stats.txt" 2> /dev/null
			}
		done
		esxcli network vswitch standard list 1> $OUTPUT_DIR/virtual/esxi/network/vswitches/standard_list.txt 2> /dev/null
		esxcli network vswitch dvs vmware list 1> $OUTPUT_DIR/virtual/esxi/network/vswitches/dvs_list.txt 2> /dev/null
		esxcli network vswitch standard list 2>/dev/null | grep "^   " | awk '{print $1}' | while read vswitch; do
			[ -n "$vswitch" ] && {
				mkdir -p "$OUTPUT_DIR/virtual/esxi/network/vswitches/$vswitch"
				esxcli network vswitch standard get -v "$vswitch" > "$OUTPUT_DIR/virtual/esxi/network/vswitches/$vswitch/config.txt" 2> /dev/null
				esxcli network vswitch standard policy security get -v "$vswitch" > "$OUTPUT_DIR/virtual/esxi/network/vswitches/$vswitch/security_policy.txt" 2> /dev/null
				esxcli network vswitch standard policy failover get -v "$vswitch" > "$OUTPUT_DIR/virtual/esxi/network/vswitches/$vswitch/failover_policy.txt" 2> /dev/null
				esxcli network vswitch standard policy shaping get -v "$vswitch" > "$OUTPUT_DIR/virtual/esxi/network/vswitches/$vswitch/shaping_policy.txt" 2> /dev/null
				esxcli network vswitch standard portgroup list -v "$vswitch" > "$OUTPUT_DIR/virtual/esxi/network/vswitches/$vswitch/portgroups.txt" 2> /dev/null
			}
		done
		esxcli network vswitch standard portgroup list 1> $OUTPUT_DIR/virtual/esxi/network/portgroups/all_portgroups.txt 2> /dev/null
		esxcli network vm list 1> $OUTPUT_DIR/virtual/esxi/network/vm_networks.txt 2> /dev/null
		
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi storage configuration"
		esxcli storage filesystem list 1> $OUTPUT_DIR/virtual/esxi/storage/filesystems.txt 2> /dev/null
		esxcli storage vmfs extent list 1> $OUTPUT_DIR/virtual/esxi/storage/vmfs_extents.txt 2> /dev/null
		esxcli storage vmfs snapshot list 1> $OUTPUT_DIR/virtual/esxi/storage/vmfs_snapshots.txt 2> /dev/null
		esxcli storage core adapter list 1> $OUTPUT_DIR/virtual/esxi/storage/adapters/list.txt 2> /dev/null
		esxcli storage core adapter stats get 1> $OUTPUT_DIR/virtual/esxi/storage/adapters/stats.txt 2> /dev/null
		esxcli storage core device list 1> $OUTPUT_DIR/virtual/esxi/storage/devices/list.txt 2> /dev/null
		esxcli storage core device stats get 1> $OUTPUT_DIR/virtual/esxi/storage/devices/stats.txt 2> /dev/null
		esxcli storage core device partition list 1> $OUTPUT_DIR/virtual/esxi/storage/devices/partitions.txt 2> /dev/null
		esxcli storage core device vaai status get 1> $OUTPUT_DIR/virtual/esxi/storage/devices/vaai_status.txt 2> /dev/null
		esxcli storage core path list 1> $OUTPUT_DIR/virtual/esxi/storage/paths.txt 2> /dev/null
		esxcli storage core path stats get 1> $OUTPUT_DIR/virtual/esxi/storage/path_stats.txt 2> /dev/null
		esxcli storage core plugin list 1> $OUTPUT_DIR/virtual/esxi/storage/plugins.txt 2> /dev/null
		esxcli storage nfs list 1> $OUTPUT_DIR/virtual/esxi/storage/nfs_list.txt 2> /dev/null
		esxcli storage nfs41 list 1> $OUTPUT_DIR/virtual/esxi/storage/nfs41_list.txt 2> /dev/null
		esxcli iscsi adapter list 1> $OUTPUT_DIR/virtual/esxi/storage/iscsi/adapters.txt 2> /dev/null
		esxcli iscsi session list 1> $OUTPUT_DIR/virtual/esxi/storage/iscsi/sessions.txt 2> /dev/null
		esxcli iscsi connection list 1> $OUTPUT_DIR/virtual/esxi/storage/iscsi/connections.txt 2> /dev/null
		esxcli iscsi ibftboot get 1> $OUTPUT_DIR/virtual/esxi/storage/iscsi/boot_config.txt 2> /dev/null
		esxcli iscsi networkportal list 1> $OUTPUT_DIR/virtual/esxi/storage/iscsi/network_portals.txt 2> /dev/null
		esxcli iscsi physicalnetworkportal list 1> $OUTPUT_DIR/virtual/esxi/storage/iscsi/physical_portals.txt 2> /dev/null
		esxcli iscsi plugin list 1> $OUTPUT_DIR/virtual/esxi/storage/iscsi/plugins.txt 2> /dev/null
		esxcli iscsi software get 1> $OUTPUT_DIR/virtual/esxi/storage/iscsi/software_iscsi.txt 2> /dev/null
		esxcli vsan cluster get 1> $OUTPUT_DIR/virtual/esxi/storage/vsan/cluster.txt 2> /dev/null
		esxcli vsan network list 1> $OUTPUT_DIR/virtual/esxi/storage/vsan/network.txt 2> /dev/null
		esxcli vsan storage list 1> $OUTPUT_DIR/virtual/esxi/storage/vsan/storage.txt 2> /dev/null
		esxcli vsan policy getdefault 1> $OUTPUT_DIR/virtual/esxi/storage/vsan/default_policy.txt 2> /dev/null
		esxcli vsan health cluster list 1> $OUTPUT_DIR/virtual/esxi/storage/vsan/health.txt 2> /dev/null
		esxcli vsan datastore list 1> $OUTPUT_DIR/virtual/esxi/storage/vsan/datastores.txt 2> /dev/null
		esxcli vsan trace get 1> $OUTPUT_DIR/virtual/esxi/storage/vsan/trace_config.txt 2> /dev/null

		if [ -x "$(command -v vim-cmd)" ]; then
			vim-cmd hostsvc/datastore/listsummary > $OUTPUT_DIR/virtual/esxi/storage/datastores/summary.txt 2> /dev/null
			vim-cmd hostsvc/datastore/list > $OUTPUT_DIR/virtual/esxi/storage/datastores/list.txt 2> /dev/null

			vim-cmd hostsvc/datastore/list 2>/dev/null | grep -E "url.*\"" | sed 's/.*"\(.*\)".*/\1/' | while read ds_path; do
				if [ -n "$ds_path" ]; then
					DS_NAME=$(basename "$ds_path")
					vim-cmd hostsvc/datastore/info "$ds_path" > "$OUTPUT_DIR/virtual/esxi/storage/datastores/${DS_NAME}_info.txt" 2> /dev/null
				fi
			done
		fi

		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi virtual machine information"
		esxcli vm process list 1> $OUTPUT_DIR/virtual/esxi/vms/process_list.txt 2> /dev/null
		
		if [ -x "$(command -v vim-cmd)" ]; then
			vim-cmd vmsvc/getallvms 1> $OUTPUT_DIR/virtual/esxi/vms/all_vms.txt 2> /dev/null
			
			vim-cmd vmsvc/getallvms 2>/dev/null | awk 'NR>1 {print $1}' | while read vmid; do
				if [ -n "$vmid" ] && [ "$vmid" -eq "$vmid" ] 2>/dev/null; then
					echo "  ${COL_ENTRY}>${RESET} Processing VM ID: $vmid"
					
					# Get VM name for directory
					VM_NAME=$(vim-cmd vmsvc/get.summary $vmid 2>/dev/null | grep -E "name = " | head -1 | sed 's/.*= "\(.*\)".*/\1/' | sed 's/[^a-zA-Z0-9._-]/_/g')
					[ -z "$VM_NAME" ] && VM_NAME="vm_$vmid"
					
					mkdir -p "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME"
					vim-cmd vmsvc/get.summary $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/summary.txt" 2> /dev/null
					vim-cmd vmsvc/get.config $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/config.txt" 2> /dev/null
					vim-cmd vmsvc/get.runtime $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/runtime.txt" 2> /dev/null
					vim-cmd vmsvc/get.guest $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/guest.txt" 2> /dev/null
					vim-cmd vmsvc/get.datastores $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/datastores.txt" 2> /dev/null
					vim-cmd vmsvc/get.networks $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/networks.txt" 2> /dev/null
					vim-cmd vmsvc/get.snapshot $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/snapshots.txt" 2> /dev/null
					vim-cmd vmsvc/device.getdevices $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/devices.txt" 2> /dev/null
					vim-cmd vmsvc/get.tasklist $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/tasks.txt" 2> /dev/null
					vim-cmd vmsvc/get.filelayout $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/filelayout.txt" 2> /dev/null
					vim-cmd vmsvc/guestinfo $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/guestinfo.txt" 2> /dev/null
					vim-cmd vmsvc/message $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/messages.txt" 2> /dev/null
					vim-cmd vmsvc/get.environment $vmid > "$OUTPUT_DIR/virtual/esxi/vms/$VM_NAME/environment.txt" 2> /dev/null
				fi
			done
		fi

		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi security configuration"
		esxcli network firewall get 1> $OUTPUT_DIR/virtual/esxi/security/firewall_status.txt 2> /dev/null
		esxcli network firewall ruleset list 1> $OUTPUT_DIR/virtual/esxi/security/firewall_rulesets.txt 2> /dev/null
		esxcli network firewall ruleset rule list 1> $OUTPUT_DIR/virtual/esxi/security/firewall_rules.txt 2> /dev/null
		esxcli network firewall ruleset allowedip list 1> $OUTPUT_DIR/virtual/esxi/security/firewall_allowed_ips.txt 2> /dev/null
		esxcli system account list 1> $OUTPUT_DIR/virtual/esxi/security/accounts.txt 2> /dev/null
		esxcli system permission list 1> $OUTPUT_DIR/virtual/esxi/security/permissions.txt 2> /dev/null
		esxcli system security certificatestore list 1> $OUTPUT_DIR/virtual/esxi/security/certificates.txt 2> /dev/null
		esxcli software acceptance get 1> $OUTPUT_DIR/virtual/esxi/security/software_acceptance.txt 2> /dev/null
		
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi advanced configuration"
		esxcli system settings advanced list 1> $OUTPUT_DIR/virtual/esxi/config/advanced_settings.txt 2> /dev/null
		esxcli system settings kernel list 1> $OUTPUT_DIR/virtual/esxi/config/kernel_settings.txt 2> /dev/null
		esxcli system syslog config get 1> $OUTPUT_DIR/virtual/esxi/config/syslog_config.txt 2> /dev/null
		esxcli system syslog config logger list 1> $OUTPUT_DIR/virtual/esxi/config/syslog_loggers.txt 2> /dev/null
		esxcli system coredump file list 1> $OUTPUT_DIR/virtual/esxi/config/coredump_files.txt 2> /dev/null
		esxcli system coredump file get 1> $OUTPUT_DIR/virtual/esxi/config/coredump_active.txt 2> /dev/null
		esxcli system coredump network get 1> $OUTPUT_DIR/virtual/esxi/config/coredump_network.txt 2> /dev/null
		esxcli system coredump partition list 1> $OUTPUT_DIR/virtual/esxi/config/coredump_partitions.txt 2> /dev/null
		
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi services information"
		esxcli system process list 1> $OUTPUT_DIR/virtual/esxi/services/process_list.txt 2> /dev/null
		esxcli system process stats load get 1> $OUTPUT_DIR/virtual/esxi/services/process_load.txt 2> /dev/null
		esxcli system module list 1> $OUTPUT_DIR/virtual/esxi/services/kernel_modules.txt 2> /dev/null
		esxcli system module get -m vmkernel 1> $OUTPUT_DIR/virtual/esxi/services/vmkernel_info.txt 2> /dev/null
		vmkload_mod -l 1> $OUTPUT_DIR/virtual/esxi/services/loaded_modules.txt 2> /dev/null
		vmkload_mod -s 1> $OUTPUT_DIR/virtual/esxi/services/module_stats.txt 2> /dev/null
		
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi software information"
		esxcli software vib list 1> $OUTPUT_DIR/virtual/esxi/software/vib_list.txt 2> /dev/null
		esxcli software vib get 1> $OUTPUT_DIR/virtual/esxi/software/vib_details.txt 2> /dev/null
		esxcli software profile get 1> $OUTPUT_DIR/virtual/esxi/software/profile.txt 2> /dev/null
		esxcli software sources profile list 1> $OUTPUT_DIR/virtual/esxi/software/available_profiles.txt 2> /dev/null

		# Performance Data
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi performance data"
		esxtop -b -n 1 > $OUTPUT_DIR/virtual/esxi/performance/esxtop_snapshot.csv 2> /dev/null
		esxcli system stats uptime get 1> $OUTPUT_DIR/virtual/esxi/performance/uptime.txt 2> /dev/null
		esxcli hardware cpu usage get 1> $OUTPUT_DIR/virtual/esxi/performance/cpu_usage.txt 2> /dev/null
		esxcli hardware memory stats get 1> $OUTPUT_DIR/virtual/esxi/performance/memory_stats.txt 2> /dev/null
		
		echo "  ${COL_ENTRY}>${RESET} Collecting cluster information"
		esxcli system stats installtime get 1> $OUTPUT_DIR/virtual/esxi/cluster/install_time.txt 2> /dev/null
		
		echo "  ${COL_ENTRY}>${RESET} Collecting ESXi logs"
		
		ls -la /var/log/ > $OUTPUT_DIR/virtual/esxi/logs/var_log_listing.txt 2> /dev/null
		ls -la /scratch/log/ > $OUTPUT_DIR/virtual/esxi/logs/scratch_log_listing.txt 2> /dev/null
		
		for logfile in /var/log/vmkernel.log /var/log/vmkwarning.log /var/log/hostd.log /var/log/vpxa.log /var/log/fdm.log /var/log/shell.log /var/log/auth.log /var/log/esxi*.log; do
			if [ -f "$logfile" ]; then
				LOGNAME=$(basename "$logfile")
				tail -n 40000 "$logfile" > "$OUTPUT_DIR/virtual/esxi/logs/var_log/${LOGNAME}_tail10k.txt" 2> /dev/null
			fi
		done
		
		for logfile in /scratch/log/vmkernel.log /scratch/log/vmkwarning.log /scratch/log/hostd.log /scratch/log/vpxa.log; do
			if [ -f "$logfile" ]; then
				LOGNAME=$(basename "$logfile")
				tail -n 40000 "$logfile" > "$OUTPUT_DIR/virtual/esxi/logs/scratch_log/${LOGNAME}_tail10k.txt" 2> /dev/null
			fi
		done
		
		echo "  ${COL_ENTRY}>${RESET} Collecting additional diagnostic information"
		vmkerrcode -l > $OUTPUT_DIR/virtual/esxi/system/error_codes.txt 2> /dev/null
		vmkping -I vmk0 -c 1 localhost > $OUTPUT_DIR/virtual/esxi/network/vmkping_test.txt 2> /dev/null
		vm-support -V 1> $OUTPUT_DIR/virtual/esxi/system/vm_support_version.txt 2> /dev/null
	fi

	# VirtualBox
	if [ -x "$(command -v VBoxManage)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting VirtualBox information"
		mkdir -p $OUTPUT_DIR/virtual/vbox
		mkdir -p $OUTPUT_DIR/virtual/vbox/system
		mkdir -p $OUTPUT_DIR/virtual/vbox/host
		mkdir -p $OUTPUT_DIR/virtual/vbox/network
		mkdir -p $OUTPUT_DIR/virtual/vbox/storage
		mkdir -p $OUTPUT_DIR/virtual/vbox/vms
		mkdir -p $OUTPUT_DIR/virtual/vbox/vms/running
		mkdir -p $OUTPUT_DIR/virtual/vbox/extensions
		mkdir -p $OUTPUT_DIR/virtual/vbox/cloud
		mkdir -p $OUTPUT_DIR/virtual/vbox/usb
		mkdir -p $OUTPUT_DIR/virtual/vbox/config
		mkdir -p $OUTPUT_DIR/virtual/vbox/logs
		mkdir -p $OUTPUT_DIR/virtual/vbox/metrics
		
		# System Information
		echo "  ${COL_ENTRY}>${RESET} Collecting VirtualBox system information"
		VBoxManage --version > $OUTPUT_DIR/virtual/vbox/system/version.txt 2> /dev/null
		VBoxManage list systemproperties > $OUTPUT_DIR/virtual/vbox/system/properties.txt 2> /dev/null
		VBoxManage list ostypes > $OUTPUT_DIR/virtual/vbox/system/supported_os_types.txt 2> /dev/null
		VBoxManage list hddbackends > $OUTPUT_DIR/virtual/vbox/system/hdd_backends.txt 2> /dev/null
		VBoxManage getextradata global enumerate > $OUTPUT_DIR/virtual/vbox/system/global_extradata.txt 2> /dev/null
		
		# Extract key paths from system properties
		VBOX_HOME=$(VBoxManage list systemproperties 2>/dev/null | grep "Default machine folder:" | sed 's/Default machine folder:[ ]*//')
		VBOX_LOG_FOLDER=$(VBoxManage list systemproperties 2>/dev/null | grep "Log folder:" | sed 's/Log folder:[ ]*//')
		VBOX_VRDP_AUTH=$(VBoxManage list systemproperties 2>/dev/null | grep "VRDE auth library:" | sed 's/VRDE auth library:[ ]*//')

		# Host Information
		echo "  ${COL_ENTRY}>${RESET} Collecting host system information"
		VBoxManage list hostinfo > $OUTPUT_DIR/virtual/vbox/host/info.txt 2> /dev/null
		VBoxManage list hostcpuids > $OUTPUT_DIR/virtual/vbox/host/cpuids.txt 2> /dev/null
		VBoxManage list hostdrives > $OUTPUT_DIR/virtual/vbox/host/drives.txt 2> /dev/null
		VBoxManage list hostdvds > $OUTPUT_DIR/virtual/vbox/host/dvds.txt 2> /dev/null
		VBoxManage list hostfloppies > $OUTPUT_DIR/virtual/vbox/host/floppies.txt 2> /dev/null
		
		# Network Configuration
		echo "  ${COL_ENTRY}>${RESET} Collecting VirtualBox network configuration"
		VBoxManage list hostonlyifs > $OUTPUT_DIR/virtual/vbox/network/hostonly_interfaces.txt 2> /dev/null
		VBoxManage list hostonlynets > $OUTPUT_DIR/virtual/vbox/network/hostonly_networks.txt 2> /dev/null
		VBoxManage list bridgedifs > $OUTPUT_DIR/virtual/vbox/network/bridged_interfaces.txt 2> /dev/null
		VBoxManage list natnets > $OUTPUT_DIR/virtual/vbox/network/nat_networks.txt 2> /dev/null
		VBoxManage list intnets > $OUTPUT_DIR/virtual/vbox/network/internal_networks.txt 2> /dev/null
		VBoxManage list dhcpservers > $OUTPUT_DIR/virtual/vbox/network/dhcp_servers.txt 2> /dev/null
		VBoxManage natnetwork list > $OUTPUT_DIR/virtual/vbox/network/natnetwork_list.txt 2> /dev/null
		
		# Detailed network configuration for each NAT network
		VBoxManage list natnets 2>/dev/null | grep "NetworkName:" | awk '{print $2}' | while read natnet; do
			[ -n "$natnet" ] && VBoxManage natnetwork showconfig "$natnet" > "$OUTPUT_DIR/virtual/vbox/network/natnet_${natnet}_config.txt" 2> /dev/null
		done
		
		# Storage Information
		echo "  ${COL_ENTRY}>${RESET} Collecting VirtualBox storage information"
		VBoxManage list hdds > $OUTPUT_DIR/virtual/vbox/storage/hdds.txt 2> /dev/null
		VBoxManage list dvds > $OUTPUT_DIR/virtual/vbox/storage/dvds.txt 2> /dev/null
		VBoxManage list floppies > $OUTPUT_DIR/virtual/vbox/storage/floppies.txt 2> /dev/null
		
		# Storage bandwidth groups
		VBoxManage bandwidthctl list > $OUTPUT_DIR/virtual/vbox/storage/bandwidth_groups.txt 2> /dev/null
		
		# USB Configuration
		echo "  ${COL_ENTRY}>${RESET} Collecting USB configuration"
		VBoxManage list usbhost > $OUTPUT_DIR/virtual/vbox/usb/host_devices.txt 2> /dev/null
		VBoxManage list usbfilters > $OUTPUT_DIR/virtual/vbox/usb/filters.txt 2> /dev/null
		
		# Extensions and Cloud
		echo "  ${COL_ENTRY}>${RESET} Collecting extensions and cloud information"
		VBoxManage list extpacks > $OUTPUT_DIR/virtual/vbox/extensions/extpacks.txt 2> /dev/null
		VBoxManage list cloudproviders > $OUTPUT_DIR/virtual/vbox/cloud/providers.txt 2> /dev/null
		VBoxManage list cloudprofiles > $OUTPUT_DIR/virtual/vbox/cloud/profiles.txt 2> /dev/null
		VBoxManage list cloudnetworks > $OUTPUT_DIR/virtual/vbox/cloud/networks.txt 2> /dev/null
		
		# Check for Guest Additions
		VBoxManage list extpacks | grep -i "guest" > $OUTPUT_DIR/virtual/vbox/extensions/guest_additions_info.txt 2> /dev/null
		
		# Virtual Machine Lists
		echo "  ${COL_ENTRY}>${RESET} Collecting virtual machine lists"
		VBoxManage list vms > $OUTPUT_DIR/virtual/vbox/vms/all_vms.txt 2> /dev/null
		VBoxManage list runningvms > $OUTPUT_DIR/virtual/vbox/vms/running_vms.txt 2> /dev/null
		VBoxManage list groups > $OUTPUT_DIR/virtual/vbox/vms/groups.txt 2> /dev/null
		
		# Detailed VM listing
		VBoxManage list vms --long > $OUTPUT_DIR/virtual/vbox/vms/all_vms_detailed.txt 2> /dev/null
		
		# Get VM names and UUIDs for detailed collection
		VBoxManage list vms | grep -E '^".*" \{' | while IFS='{' read name uuid; do
			VM_NAME=$(echo "$name" | sed 's/^"\(.*\)".*$/\1/')
			VM_UUID=$(echo "$uuid" | sed 's/}.*$//')
			
			if [ -n "$VM_NAME" ]; then
				echo "  ${COL_ENTRY}>${RESET} Processing VM: $VM_NAME"
				
				# Sanitize VM name for directory
				SAFE_NAME=$(echo "$VM_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g')
				VM_DIR="$OUTPUT_DIR/virtual/vbox/vms/$SAFE_NAME"
				mkdir -p "$VM_DIR"
				VBoxManage showvminfo "$VM_NAME" --details > "$VM_DIR/showvminfo_detailed.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable > "$VM_DIR/showvminfo_machinereadable.txt" 2> /dev/null
				VBoxManage getextradata "$VM_NAME" enumerate > "$VM_DIR/extradata.txt" 2> /dev/null
				VBoxManage snapshot "$VM_NAME" list --machinereadable > "$VM_DIR/snapshots_machinereadable.txt" 2> /dev/null
				VBoxManage snapshot "$VM_NAME" list > "$VM_DIR/snapshots.txt" 2> /dev/null
				VBoxManage guestproperty enumerate "$VM_NAME" > "$VM_DIR/guest_properties.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "storagecontroller|IDE|SATA|SCSI|SAS|USB|NVMe|hdd|dvd|floppy" > "$VM_DIR/storage_config.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "nic[0-9]|macaddress|cableconnected|bridgeadapter|hostonlyadapter|intnet|natnet|genericdrv" > "$VM_DIR/network_config.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "usb|usbfilter" > "$VM_DIR/usb_config.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "SharedFolder" > "$VM_DIR/shared_folders.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "VMState|VMStateChangeTime" > "$VM_DIR/state.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "vram|monitor|video|3d|2d" > "$VM_DIR/video_config.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "audio" > "$VM_DIR/audio_config.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "boot[0-9]|firmware" > "$VM_DIR/boot_config.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "cpus|memory|pagefusion|hpet|hwvirtex|nestedpaging|largepages|vtxvpid|vtxux" > "$VM_DIR/cpu_memory_config.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "teleporter|fault" > "$VM_DIR/ha_config.txt" 2> /dev/null
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E "videocap|recording" > "$VM_DIR/recording_config.txt" 2> /dev/null
				VBoxManage debugvm "$VM_NAME" info > "$VM_DIR/debug_info.txt" 2> /dev/null
				VBoxManage bandwidthctl "$VM_NAME" list > "$VM_DIR/bandwidth_groups.txt" 2> /dev/null
				if VBoxManage list runningvms | grep -q "\"$VM_NAME\""; then
					echo "Running" > "$VM_DIR/running_state.txt"
					VBoxManage debugvm "$VM_NAME" statistics > "$VM_DIR/runtime_statistics.txt" 2> /dev/null
					VBoxManage metrics query "$VM_NAME" > "$VM_DIR/metrics.txt" 2> /dev/null
					VBoxManage guestcontrol "$VM_NAME" list all > "$VM_DIR/guest_control.txt" 2> /dev/null
				fi
				VBoxManage showvminfo "$VM_NAME" --machinereadable | grep "LogFldr" | sed 's/LogFldr="\(.*\)"/\1/' > "$VM_DIR/log_location.txt" 2> /dev/null
			fi
		done
		
		echo "  ${COL_ENTRY}>${RESET} Collecting VirtualBox metrics"
		VBoxManage metrics list > $OUTPUT_DIR/virtual/vbox/metrics/available_metrics.txt 2> /dev/null
		VBoxManage metrics query > $OUTPUT_DIR/virtual/vbox/metrics/current_metrics.txt 2> /dev/null
	
		echo "  ${COL_ENTRY}>${RESET} Locating VirtualBox configuration and logs"
		
		for homedir in /home/* /root; do
			if [ -d "$homedir/.VirtualBox" ]; then
				echo "Found VirtualBox config in: $homedir/.VirtualBox" >> $OUTPUT_DIR/virtual/vbox/config/locations.txt
				ls -la "$homedir/.VirtualBox/" >> $OUTPUT_DIR/virtual/vbox/config/locations.txt 2> /dev/null
				# Copy main config files
				[ -f "$homedir/.VirtualBox/VirtualBox.xml" ] && cp "$homedir/.VirtualBox/VirtualBox.xml" "$OUTPUT_DIR/virtual/vbox/config/VirtualBox_$(basename $homedir).xml" 2> /dev/null
				# List extension packs
				[ -d "$homedir/.VirtualBox/ExtensionPacks" ] && ls -la "$homedir/.VirtualBox/ExtensionPacks/" >> $OUTPUT_DIR/virtual/vbox/extensions/installed_packs.txt 2> /dev/null
			fi
			
			if [ -d "$homedir/VirtualBox VMs" ]; then
				echo "Found VirtualBox VMs in: $homedir/VirtualBox VMs" >> $OUTPUT_DIR/virtual/vbox/vms/vm_locations.txt
				find "$homedir/VirtualBox VMs" -name "*.vbox" -o -name "*.vbox-prev" 2>/dev/null | head -100 >> $OUTPUT_DIR/virtual/vbox/vms/vm_files.txt
			fi
		done

		if [ -n "$VBOX_HOME" ] && [ -d "$VBOX_HOME" ]; then
			echo "VirtualBox Home: $VBOX_HOME" > $OUTPUT_DIR/virtual/vbox/logs/log_locations.txt
			find "$VBOX_HOME" -name "*.log" -type f -mtime -7 2>/dev/null | head -100 >> $OUTPUT_DIR/virtual/vbox/logs/recent_logs.txt
			find "$VBOX_HOME" -name "VBox.log*" -type f 2>/dev/null | head -50 >> $OUTPUT_DIR/virtual/vbox/logs/vbox_logs.txt
		fi
		
		for svc_file in /etc/init.d/vboxdrv /etc/systemd/system/vbox*.service /lib/systemd/system/vbox*.service; do
			[ -f "$svc_file" ] && {
				echo "Found service file: $svc_file" >> $OUTPUT_DIR/virtual/vbox/system/service_files.txt
				ls -la "$svc_file" >> $OUTPUT_DIR/virtual/vbox/system/service_files.txt 2> /dev/null
			}
		done
		
		lsmod | grep -i vbox > $OUTPUT_DIR/virtual/vbox/system/kernel_modules.txt 2> /dev/null
	fi
	# VIRT (KVM/QEMU with libvirt)
	if [ -x "$(command -v virsh)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting KVM/QEMU information"
		
		# Create organized directory structure
		mkdir -p $OUTPUT_DIR/virtual/virt
		mkdir -p $OUTPUT_DIR/virtual/virt/system
		mkdir -p $OUTPUT_DIR/virtual/virt/host
		mkdir -p $OUTPUT_DIR/virtual/virt/capabilities
		mkdir -p $OUTPUT_DIR/virtual/virt/vms
		mkdir -p $OUTPUT_DIR/virtual/virt/vms/running
		mkdir -p $OUTPUT_DIR/virtual/virt/vms/configs
		mkdir -p $OUTPUT_DIR/virtual/virt/networks
		mkdir -p $OUTPUT_DIR/virtual/virt/storage
		mkdir -p $OUTPUT_DIR/virtual/virt/storage/pools
		mkdir -p $OUTPUT_DIR/virtual/virt/storage/volumes
		mkdir -p $OUTPUT_DIR/virtual/virt/interfaces
		mkdir -p $OUTPUT_DIR/virtual/virt/devices
		mkdir -p $OUTPUT_DIR/virtual/virt/secrets
		mkdir -p $OUTPUT_DIR/virtual/virt/nwfilters
		mkdir -p $OUTPUT_DIR/virtual/virt/checkpoints
		mkdir -p $OUTPUT_DIR/virtual/virt/logs
		
		# System Information
		echo "  ${COL_ENTRY}>${RESET} Collecting libvirt system information"
		virsh version > $OUTPUT_DIR/virtual/virt/system/version.txt 2> /dev/null
		virsh version --daemon > $OUTPUT_DIR/virtual/virt/system/version_daemon.txt 2> /dev/null
		virsh hostname > $OUTPUT_DIR/virtual/virt/system/hostname.txt 2> /dev/null
		virsh uri > $OUTPUT_DIR/virtual/virt/system/uri.txt 2> /dev/null
		virsh connect > $OUTPUT_DIR/virtual/virt/system/connection.txt 2> /dev/null
		virsh sysinfo > $OUTPUT_DIR/virtual/virt/system/sysinfo.txt 2> /dev/null
		
		# Check libvirt service status
		systemctl status libvirtd --no-pager > $OUTPUT_DIR/virtual/virt/system/libvirtd_status.txt 2> /dev/null
		systemctl status virtlogd --no-pager > $OUTPUT_DIR/virtual/virt/system/virtlogd_status.txt 2> /dev/null
		systemctl status virtlockd --no-pager > $OUTPUT_DIR/virtual/virt/system/virtlockd_status.txt 2> /dev/null
		
		# Host Information
		echo "  ${COL_ENTRY}>${RESET} Collecting host information"
		virsh nodeinfo > $OUTPUT_DIR/virtual/virt/host/nodeinfo.txt 2> /dev/null
		virsh nodecpumap > $OUTPUT_DIR/virtual/virt/host/cpumap.txt 2> /dev/null
		virsh nodecpustats > $OUTPUT_DIR/virtual/virt/host/cpustats.txt 2> /dev/null
		virsh nodememstats > $OUTPUT_DIR/virtual/virt/host/memstats.txt 2> /dev/null
		virsh nodesuspend --target mem --duration 0 2>&1 | grep -E "error|capability" > $OUTPUT_DIR/virtual/virt/host/suspend_capabilities.txt 2> /dev/null
		virsh maxvcpus > $OUTPUT_DIR/virtual/virt/host/maxvcpus.txt 2> /dev/null
		virsh freecell --all > $OUTPUT_DIR/virtual/virt/host/freecell.txt 2> /dev/null
		virsh freepages --all > $OUTPUT_DIR/virtual/virt/host/freepages.txt 2> /dev/null
		
		# Capabilities
		echo "  ${COL_ENTRY}>${RESET} Collecting capabilities information"
		virsh capabilities > $OUTPUT_DIR/virtual/virt/capabilities/capabilities.xml 2> /dev/null
		virsh domcapabilities > $OUTPUT_DIR/virtual/virt/capabilities/domain_capabilities.xml 2> /dev/null
		virsh domcapabilities --machine pc > $OUTPUT_DIR/virtual/virt/capabilities/domain_capabilities_pc.xml 2> /dev/null
		virsh domcapabilities --machine q35 > $OUTPUT_DIR/virtual/virt/capabilities/domain_capabilities_q35.xml 2> /dev/null
		
		# Virtual Machine Lists
		echo "  ${COL_ENTRY}>${RESET} Collecting virtual machine lists"
		virsh list --all > $OUTPUT_DIR/virtual/virt/vms/all_vms.txt 2> /dev/null
		virsh list --all --name > $OUTPUT_DIR/virtual/virt/vms/all_vms_names.txt 2> /dev/null
		virsh list --all --uuid > $OUTPUT_DIR/virtual/virt/vms/all_vms_uuids.txt 2> /dev/null
		virsh list --all --title > $OUTPUT_DIR/virtual/virt/vms/all_vms_titles.txt 2> /dev/null
		virsh list --all --managed-save > $OUTPUT_DIR/virtual/virt/vms/vms_with_managed_save.txt 2> /dev/null
		virsh list --all --with-snapshot > $OUTPUT_DIR/virtual/virt/vms/vms_with_snapshots.txt 2> /dev/null
		virsh list --all --with-checkpoint > $OUTPUT_DIR/virtual/virt/vms/vms_with_checkpoints.txt 2> /dev/null
		
		# Detailed VM collection
		echo "  ${COL_ENTRY}>${RESET} Collecting detailed VM information"
		virsh list --all --name 2>/dev/null | while read vm; do
			if [ -n "$vm" ]; then
				echo "  ${COL_ENTRY}>${RESET} Processing VM: $vm"
				
				# Sanitize VM name for directory
				SAFE_NAME=$(echo "$vm" | sed 's/[^a-zA-Z0-9._-]/_/g')
				VM_DIR="$OUTPUT_DIR/virtual/virt/vms/$SAFE_NAME"
				mkdir -p "$VM_DIR"
				mkdir -p "$VM_DIR/snapshots"
				mkdir -p "$VM_DIR/checkpoints"
				mkdir -p "$VM_DIR/storage"
				mkdir -p "$VM_DIR/network"
				mkdir -p "$VM_DIR/stats"
				
				# Basic VM information
				virsh dominfo "$vm" > "$VM_DIR/dominfo.txt" 2> /dev/null
				virsh domstate "$vm" --reason > "$VM_DIR/state.txt" 2> /dev/null
				virsh domuuid "$vm" > "$VM_DIR/uuid.txt" 2> /dev/null
				virsh domid "$vm" > "$VM_DIR/id.txt" 2> /dev/null
				virsh domname "$vm" > "$VM_DIR/name.txt" 2> /dev/null
				
				# VM configuration (XML)
				virsh dumpxml "$vm" > "$VM_DIR/config.xml" 2> /dev/null
				virsh dumpxml "$vm" --inactive > "$VM_DIR/config_inactive.xml" 2> /dev/null
				virsh dumpxml "$vm" --security-info > "$VM_DIR/config_with_security.xml" 2> /dev/null
				virsh dumpxml "$vm" --update-cpu > "$VM_DIR/config_update_cpu.xml" 2> /dev/null
				
				# CPU information
				virsh vcpuinfo "$vm" > "$VM_DIR/vcpuinfo.txt" 2> /dev/null
				virsh vcpucount "$vm" > "$VM_DIR/vcpucount.txt" 2> /dev/null
				virsh vcpupin "$vm" > "$VM_DIR/vcpupin.txt" 2> /dev/null
				virsh emulatorpin "$vm" > "$VM_DIR/emulatorpin.txt" 2> /dev/null
				virsh cpu-stats "$vm" --total > "$VM_DIR/stats/cpu_stats_total.txt" 2> /dev/null
				virsh cpu-stats "$vm" > "$VM_DIR/stats/cpu_stats.txt" 2> /dev/null
				
				# Memory information
				virsh dommemstat "$vm" > "$VM_DIR/stats/memstat.txt" 2> /dev/null
				virsh domblkstat "$vm" --human > "$VM_DIR/stats/blkstat_human.txt" 2> /dev/null
				virsh memtune "$vm" > "$VM_DIR/memtune.txt" 2> /dev/null
				virsh numatune "$vm" > "$VM_DIR/numatune.txt" 2> /dev/null
				
				# Storage devices
				virsh domblklist "$vm" --details > "$VM_DIR/storage/blklist.txt" 2> /dev/null
				virsh domblklist "$vm" --inactive > "$VM_DIR/storage/blklist_inactive.txt" 2> /dev/null
				
				# Get detailed stats for each block device
				virsh domblklist "$vm" 2>/dev/null | tail -n +3 | awk '{print $1}' | while read device; do
					if [ -n "$device" ]; then
						virsh domblkstat "$vm" "$device" > "$VM_DIR/storage/blkstat_${device//\//_}.txt" 2> /dev/null
						virsh domblkinfo "$vm" "$device" > "$VM_DIR/storage/blkinfo_${device//\//_}.txt" 2> /dev/null
						virsh domblkthreshold "$vm" "$device" > "$VM_DIR/storage/blkthreshold_${device//\//_}.txt" 2> /dev/null
						virsh domblkerror "$vm" > "$VM_DIR/storage/blkerror.txt" 2> /dev/null
					fi
				done
				
				# Network interfaces
				virsh domiflist "$vm" > "$VM_DIR/network/iflist.txt" 2> /dev/null
				virsh domiflist "$vm" --inactive > "$VM_DIR/network/iflist_inactive.txt" 2> /dev/null
				
				# Get detailed stats for each network interface
				virsh domiflist "$vm" 2>/dev/null | tail -n +3 | awk '{print $1}' | while read iface; do
					if [ -n "$iface" ]; then
						virsh domifstat "$vm" "$iface" > "$VM_DIR/network/ifstat_${iface}.txt" 2> /dev/null
						virsh domif-getlink "$vm" "$iface" > "$VM_DIR/network/iflink_${iface}.txt" 2> /dev/null
					fi
				done
				
				# Snapshots
				virsh snapshot-list "$vm" --tree > "$VM_DIR/snapshots/tree.txt" 2> /dev/null
				virsh snapshot-list "$vm" --details > "$VM_DIR/snapshots/list_details.txt" 2> /dev/null
				virsh snapshot-list "$vm" --parent > "$VM_DIR/snapshots/list_parent.txt" 2> /dev/null
				virsh snapshot-list "$vm" --roots > "$VM_DIR/snapshots/roots.txt" 2> /dev/null
				virsh snapshot-list "$vm" --leaves > "$VM_DIR/snapshots/leaves.txt" 2> /dev/null
				
				# Get XML for each snapshot
				virsh snapshot-list "$vm" --name 2>/dev/null | while read snap; do
					if [ -n "$snap" ]; then
						SAFE_SNAP=$(echo "$snap" | sed 's/[^a-zA-Z0-9._-]/_/g')
						virsh snapshot-dumpxml "$vm" "$snap" > "$VM_DIR/snapshots/${SAFE_SNAP}.xml" 2> /dev/null
					fi
				done
				
				# Checkpoints (if supported)
				virsh checkpoint-list "$vm" > "$VM_DIR/checkpoints/list.txt" 2> /dev/null
				virsh checkpoint-list "$vm" --tree > "$VM_DIR/checkpoints/tree.txt" 2> /dev/null
				
				# Guest information (if agent is running)
				virsh domfsinfo "$vm" > "$VM_DIR/guest_fsinfo.txt" 2> /dev/null
				virsh domhostname "$vm" > "$VM_DIR/guest_hostname.txt" 2> /dev/null
				virsh domifaddr "$vm" > "$VM_DIR/guest_ifaddr.txt" 2> /dev/null
				virsh domifaddr "$vm" --source agent > "$VM_DIR/guest_ifaddr_agent.txt" 2> /dev/null
				virsh domtime "$vm" > "$VM_DIR/guest_time.txt" 2> /dev/null
				virsh guestinfo "$vm" > "$VM_DIR/guest_info.txt" 2> /dev/null
				virsh guestvcpus "$vm" > "$VM_DIR/guest_vcpus.txt" 2> /dev/null
				
				# Performance and tuning
				virsh domstats "$vm" > "$VM_DIR/stats/domstats.txt" 2> /dev/null
				virsh domstats "$vm" --raw > "$VM_DIR/stats/domstats_raw.txt" 2> /dev/null
				virsh domcontrol "$vm" > "$VM_DIR/control.txt" 2> /dev/null
				virsh schedinfo "$vm" > "$VM_DIR/schedinfo.txt" 2> /dev/null
				virsh blkiotune "$vm" > "$VM_DIR/blkiotune.txt" 2> /dev/null
				virsh domiftune "$vm" > "$VM_DIR/domiftune.txt" 2> /dev/null
				
				# Security
				virsh domdisplay "$vm" > "$VM_DIR/display.txt" 2> /dev/null
				virsh domjobinfo "$vm" > "$VM_DIR/jobinfo.txt" 2> /dev/null
				virsh domlaunchsecinfo "$vm" > "$VM_DIR/launchsecinfo.txt" 2> /dev/null
				
				# Save/Restore information
				[ -f "/var/lib/libvirt/qemu/save/${vm}.save" ] && echo "Saved state exists" > "$VM_DIR/saved_state.txt"
				
				# If VM is running, collect additional runtime info
				if virsh domstate "$vm" 2>/dev/null | grep -q "running"; then
					echo "Running" > "$VM_DIR/running_state.txt"
					virsh qemu-monitor-command "$vm" --pretty '{"execute":"query-status"}' > "$VM_DIR/qemu_status.json" 2> /dev/null
					virsh qemu-monitor-command "$vm" --pretty '{"execute":"query-kvm"}' > "$VM_DIR/qemu_kvm.json" 2> /dev/null
					virsh qemu-monitor-command "$vm" --pretty '{"execute":"query-cpus"}' > "$VM_DIR/qemu_cpus.json" 2> /dev/null
					virsh qemu-monitor-command "$vm" --pretty '{"execute":"query-block"}' > "$VM_DIR/qemu_block.json" 2> /dev/null
					virsh qemu-monitor-command "$vm" --pretty '{"execute":"query-blockstats"}' > "$VM_DIR/qemu_blockstats.json" 2> /dev/null
					virsh qemu-monitor-command "$vm" --pretty '{"execute":"query-mem"}' > "$VM_DIR/qemu_mem.json" 2> /dev/null
				fi
			fi
		done
		
		# Network Configuration
		echo "  ${COL_ENTRY}>${RESET} Collecting network configuration"
		virsh net-list --all > $OUTPUT_DIR/virtual/virt/networks/list_all.txt 2> /dev/null
		virsh net-list --all --details > $OUTPUT_DIR/virtual/virt/networks/list_details.txt 2> /dev/null
		virsh net-list --all --name > $OUTPUT_DIR/virtual/virt/networks/list_names.txt 2> /dev/null
		virsh net-list --all --uuid > $OUTPUT_DIR/virtual/virt/networks/list_uuids.txt 2> /dev/null
		
		# Detailed network collection
		virsh net-list --all --name 2>/dev/null | while read net; do
			if [ -n "$net" ]; then
				echo "  ${COL_ENTRY}>${RESET} Processing network: $net"
				
				SAFE_NET=$(echo "$net" | sed 's/[^a-zA-Z0-9._-]/_/g')
				NET_DIR="$OUTPUT_DIR/virtual/virt/networks/$SAFE_NET"
				mkdir -p "$NET_DIR"
				
				# Network information
				virsh net-info "$net" > "$NET_DIR/info.txt" 2> /dev/null
				virsh net-uuid "$net" > "$NET_DIR/uuid.txt" 2> /dev/null
				virsh net-name "$net" > "$NET_DIR/name.txt" 2> /dev/null
				
				# Network configuration
				virsh net-dumpxml "$net" > "$NET_DIR/config.xml" 2> /dev/null
				virsh net-dumpxml "$net" --inactive > "$NET_DIR/config_inactive.xml" 2> /dev/null
				
				# DHCP leases
				virsh net-dhcp-leases "$net" > "$NET_DIR/dhcp_leases.txt" 2> /dev/null
				
				# Port information
				virsh net-port-list "$net" > "$NET_DIR/port_list.txt" 2> /dev/null
				virsh net-port-list "$net" --uuid > "$NET_DIR/port_list_uuid.txt" 2> /dev/null
			fi
		done
		
		# Storage Pools
		echo "  ${COL_ENTRY}>${RESET} Collecting storage pool configuration"
		virsh pool-list --all > $OUTPUT_DIR/virtual/virt/storage/pools/list_all.txt 2> /dev/null
		virsh pool-list --all --details > $OUTPUT_DIR/virtual/virt/storage/pools/list_details.txt 2> /dev/null
		virsh pool-list --all --name > $OUTPUT_DIR/virtual/virt/storage/pools/list_names.txt 2> /dev/null
		virsh pool-list --all --uuid > $OUTPUT_DIR/virtual/virt/storage/pools/list_uuids.txt 2> /dev/null
		
		# Detailed storage pool collection
		virsh pool-list --all --name 2>/dev/null | while read pool; do
			if [ -n "$pool" ]; then
				echo "  ${COL_ENTRY}>${RESET} Processing storage pool: $pool"
				
				SAFE_POOL=$(echo "$pool" | sed 's/[^a-zA-Z0-9._-]/_/g')
				POOL_DIR="$OUTPUT_DIR/virtual/virt/storage/pools/$SAFE_POOL"
				mkdir -p "$POOL_DIR"
				
				# Pool information
				virsh pool-info "$pool" > "$POOL_DIR/info.txt" 2> /dev/null
				virsh pool-uuid "$pool" > "$POOL_DIR/uuid.txt" 2> /dev/null
				virsh pool-name "$pool" > "$POOL_DIR/name.txt" 2> /dev/null
				
				# Pool configuration
				virsh pool-dumpxml "$pool" > "$POOL_DIR/config.xml" 2> /dev/null
				virsh pool-dumpxml "$pool" --inactive > "$POOL_DIR/config_inactive.xml" 2> /dev/null
				
				# Volume list
				virsh vol-list "$pool" > "$POOL_DIR/volumes.txt" 2> /dev/null
				virsh vol-list "$pool" --details > "$POOL_DIR/volumes_details.txt" 2> /dev/null
				
				# Volume details
				virsh vol-list "$pool" 2>/dev/null | tail -n +3 | awk '{print $1}' | while read vol; do
					if [ -n "$vol" ]; then
						SAFE_VOL=$(echo "$vol" | sed 's/[^a-zA-Z0-9._-]/_/g')
						virsh vol-info "$vol" --pool "$pool" > "$POOL_DIR/vol_${SAFE_VOL}_info.txt" 2> /dev/null
						virsh vol-dumpxml "$vol" --pool "$pool" > "$POOL_DIR/vol_${SAFE_VOL}_config.xml" 2> /dev/null
					fi
				done
			fi
		done
		
		# Node Devices
		echo "  ${COL_ENTRY}>${RESET} Collecting node device information"
		virsh nodedev-list > $OUTPUT_DIR/virtual/virt/devices/list.txt 2> /dev/null
		virsh nodedev-list --tree > $OUTPUT_DIR/virtual/virt/devices/tree.txt 2> /dev/null
		virsh nodedev-list --cap net > $OUTPUT_DIR/virtual/virt/devices/net_devices.txt 2> /dev/null
		virsh nodedev-list --cap pci > $OUTPUT_DIR/virtual/virt/devices/pci_devices.txt 2> /dev/null
		virsh nodedev-list --cap scsi > $OUTPUT_DIR/virtual/virt/devices/scsi_devices.txt 2> /dev/null
		virsh nodedev-list --cap storage > $OUTPUT_DIR/virtual/virt/devices/storage_devices.txt 2> /dev/null
		virsh nodedev-list --cap system > $OUTPUT_DIR/virtual/virt/devices/system_devices.txt 2> /dev/null
		virsh nodedev-list --cap usb > $OUTPUT_DIR/virtual/virt/devices/usb_devices.txt 2> /dev/null
		virsh nodedev-list --cap usb_device > $OUTPUT_DIR/virtual/virt/devices/usb_devices_detail.txt 2> /dev/null
		
		# Interfaces
		echo "  ${COL_ENTRY}>${RESET} Collecting interface information"
		virsh iface-list --all > $OUTPUT_DIR/virtual/virt/interfaces/list_all.txt 2> /dev/null
		virsh iface-list --all --inactive > $OUTPUT_DIR/virtual/virt/interfaces/list_inactive.txt 2> /dev/null
		
		# Secrets
		echo "  ${COL_ENTRY}>${RESET} Collecting secret information (not values)"
		virsh secret-list > $OUTPUT_DIR/virtual/virt/secrets/list.txt 2> /dev/null
		virsh secret-list --all > $OUTPUT_DIR/virtual/virt/secrets/list_all.txt 2> /dev/null
		
		# Network Filters
		echo "  ${COL_ENTRY}>${RESET} Collecting network filter information"
		virsh nwfilter-list > $OUTPUT_DIR/virtual/virt/nwfilters/list.txt 2> /dev/null
		virsh nwfilter-list --name 2>/dev/null | while read filter; do
			if [ -n "$filter" ]; then
				SAFE_FILTER=$(echo "$filter" | sed 's/[^a-zA-Z0-9._-]/_/g')
				virsh nwfilter-dumpxml "$filter" > "$OUTPUT_DIR/virtual/virt/nwfilters/${SAFE_FILTER}.xml" 2> /dev/null
			fi
		done
		
		# libvirt logs
		echo "  ${COL_ENTRY}>${RESET} Collecting libvirt logs"
		if [ -d /var/log/libvirt ]; then
			ls -la /var/log/libvirt/ > $OUTPUT_DIR/virtual/virt/logs/log_listing.txt 2> /dev/null
			# Copy recent logs (limit size)
			find /var/log/libvirt -name "*.log" -type f -mtime -7 -size -100M 2>/dev/null | while read logfile; do
				LOGNAME=$(basename "$logfile")
				tail -n 10000 "$logfile" > "$OUTPUT_DIR/virtual/virt/logs/${LOGNAME}_tail10k.txt" 2> /dev/null
			done
		fi
		
		# Configuration files
		echo "  ${COL_ENTRY}>${RESET} Collecting libvirt configuration"
		for conf in /etc/libvirt/libvirtd.conf /etc/libvirt/qemu.conf /etc/libvirt/lxc.conf /etc/libvirt/libxl.conf; do
			if [ -f "$conf" ]; then
				cp "$conf" "$OUTPUT_DIR/virtual/virt/system/$(basename $conf)" 2> /dev/null
			fi
		done
		
		# Check QEMU capabilities
		if [ -x "$(command -v qemu-system-x86_64)" ]; then
			qemu-system-x86_64 -version > $OUTPUT_DIR/virtual/virt/system/qemu_version.txt 2> /dev/null
		fi
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

	if [ -x "$(command -v containerd)" ] || [ -x "$(command -v ctr)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting containerd information"
		mkdir -p $OUTPUT_DIR/containers/containerd
		mkdir -p $OUTPUT_DIR/containers/containerd/config
		mkdir -p $OUTPUT_DIR/containers/containerd/namespaces
		mkdir -p $OUTPUT_DIR/containers/containerd/images
		mkdir -p $OUTPUT_DIR/containers/containerd/containers
		mkdir -p $OUTPUT_DIR/containers/containerd/snapshots
		mkdir -p $OUTPUT_DIR/containers/containerd/tasks
		mkdir -p $OUTPUT_DIR/containers/containerd/plugins
		mkdir -p $OUTPUT_DIR/containers/containerd/content
		mkdir -p $OUTPUT_DIR/containers/containerd/events
		mkdir -p $OUTPUT_DIR/containers/containerd/logs
		echo "  ${COL_ENTRY}>${RESET} Collecting containerd version and config"
		containerd --version 1> $OUTPUT_DIR/containers/containerd/version.txt 2> /dev/null
		containerd -v 1> $OUTPUT_DIR/containers/containerd/version_verbose.txt 2> /dev/null
		containerd config dump 1> $OUTPUT_DIR/containers/containerd/config/config_dump.txt 2> /dev/null
		if [ -f /etc/containerd/config.toml ]; then
			cp /etc/containerd/config.toml $OUTPUT_DIR/containers/containerd/config/config.toml 2> /dev/null
		fi
		systemctl status containerd --no-pager 1> $OUTPUT_DIR/containers/containerd/service_status.txt 2> /dev/null
		ls -la /run/containerd/ 1> $OUTPUT_DIR/containers/containerd/socket_info.txt 2> /dev/null
		if [ -x "$(command -v ctr)" ]
		then
			echo "  ${COL_ENTRY}>${RESET} Collecting detailed containerd runtime information"
			DEFAULT_NS="default"
			ctr namespace ls 1> $OUTPUT_DIR/containers/containerd/namespaces/list.txt 2> /dev/null
			ctr namespace ls -q 2>/dev/null | while read namespace; do
				[ -z "$namespace" ] && continue
				echo "  ${COL_ENTRY}>${RESET} Processing namespace: $namespace"
				mkdir -p $OUTPUT_DIR/containers/containerd/namespaces/$namespace
				ctr -n $namespace namespace stats 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/stats.txt 2> /dev/null
				echo "  ${COL_ENTRY}>${RESET} Collecting images in namespace $namespace"
				ctr -n $namespace images ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/images_list.txt 2> /dev/null
				ctr -n $namespace images ls -q 2>/dev/null | while read image; do
					[ -z "$image" ] && continue
					# Sanitize image name for filename
					safe_image=$(echo "$image" | sed 's/[^a-zA-Z0-9._-]/_/g')
					ctr -n $namespace images info $image 1> $OUTPUT_DIR/containers/containerd/images/${namespace}_${safe_image}_info.json 2> /dev/null
				done
				echo "  ${COL_ENTRY}>${RESET} Collecting containers in namespace $namespace"
				ctr -n $namespace containers ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/containers_list.txt 2> /dev/null
				ctr -n $namespace containers ls -q 2>/dev/null | while read container; do
					[ -z "$container" ] && continue
					mkdir -p $OUTPUT_DIR/containers/containerd/containers/$namespace
					ctr -n $namespace containers info $container 1> $OUTPUT_DIR/containers/containerd/containers/$namespace/${container}_info.json 2> /dev/null
					ctr -n $namespace containers label $container 1> $OUTPUT_DIR/containers/containerd/containers/$namespace/${container}_labels.txt 2> /dev/null
				done
				echo "  ${COL_ENTRY}>${RESET} Collecting tasks in namespace $namespace"
				ctr -n $namespace tasks ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/tasks_list.txt 2> /dev/null
				ctr -n $namespace tasks ls -q 2>/dev/null | while read task; do
					[ -z "$task" ] && continue
					mkdir -p $OUTPUT_DIR/containers/containerd/tasks/$namespace
					ctr -n $namespace tasks ps $task 1> $OUTPUT_DIR/containers/containerd/tasks/$namespace/${task}_processes.txt 2> /dev/null
					ctr -n $namespace tasks metrics $task 1> $OUTPUT_DIR/containers/containerd/tasks/$namespace/${task}_metrics.json 2> /dev/null
				done
				echo "  ${COL_ENTRY}>${RESET} Collecting snapshots in namespace $namespace"
				ctr -n $namespace snapshots ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/snapshots_list.txt 2> /dev/null
				ctr -n $namespace content ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/content_list.txt 2> /dev/null
				ctr -n $namespace leases ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/leases_list.txt 2> /dev/null
			done
			echo "  ${COL_ENTRY}>${RESET} Collecting plugin information"
			ctr plugins ls 1> $OUTPUT_DIR/containers/containerd/plugins/list.txt 2> /dev/null
			ctr version 1> $OUTPUT_DIR/containers/containerd/version_detailed.txt 2> /dev/null
			echo "  ${COL_ENTRY}>${RESET} Collecting recent containerd events"
			timeout 5s ctr events 2>/dev/null | head -n 100 > $OUTPUT_DIR/containers/containerd/events/recent_events.txt 2> /dev/null
			ctr content ls 1> $OUTPUT_DIR/containers/containerd/content/global_content.txt 2> /dev/null
		fi
		echo "  ${COL_ENTRY}>${RESET} Collecting containerd logs"
		if [ -x "$(command -v journalctl)" ]; then
			journalctl -u containerd --no-pager -n 1000 1> $OUTPUT_DIR/containers/containerd/logs/journal_containerd.txt 2> /dev/null
			journalctl -u containerd --no-pager --since "24 hours ago" 1> $OUTPUT_DIR/containers/containerd/logs/journal_containerd_24h.txt 2> /dev/null
		fi
		for log in /var/log/containerd.log /var/log/containerd/*.log; do
			[ -f "$log" ] && cp "$log" $OUTPUT_DIR/containers/containerd/logs/ 2> /dev/null
		done
		echo "  ${COL_ENTRY}>${RESET} Collecting runtime information"
		for runtime_dir in /run/containerd /var/run/containerd; do
			if [ -d "$runtime_dir" ]; then
				ls -laR "$runtime_dir" 1> $OUTPUT_DIR/containers/containerd/runtime_directory_${runtime_dir##*/}.txt 2> /dev/null
			fi
		done
		if [ -d /var/lib/containerd ]; then
			echo "  ${COL_ENTRY}>${RESET} Collecting state directory information"
			find /var/lib/containerd -type d 2>/dev/null | head -1000 > $OUTPUT_DIR/containers/containerd/state_directory_structure.txt
			du -sh /var/lib/containerd/* 2>/dev/null > $OUTPUT_DIR/containers/containerd/state_directory_sizes.txt
		fi
		if [ -d /etc/cni/net.d ]; then
			echo "  ${COL_ENTRY}>${RESET} Collecting CNI network configuration"
			mkdir -p $OUTPUT_DIR/containers/containerd/network
			cp -r /etc/cni/net.d $OUTPUT_DIR/containers/containerd/network/ 2> /dev/null
		fi
		if [ -S /run/containerd/containerd.sock ]; then
			echo "  ${COL_ENTRY}>${RESET} Checking CRI integration"
			if [ -x "$(command -v crictl)" ]; then
				export CONTAINER_RUNTIME_ENDPOINT=unix:///run/containerd/containerd.sock
				mkdir -p $OUTPUT_DIR/containers/containerd/cri
				crictl version 1> $OUTPUT_DIR/containers/containerd/cri/version.txt 2> /dev/null
				crictl info 1> $OUTPUT_DIR/containers/containerd/cri/info.json 2> /dev/null
				crictl images 1> $OUTPUT_DIR/containers/containerd/cri/images.txt 2> /dev/null
				crictl pods 1> $OUTPUT_DIR/containers/containerd/cri/pods.txt 2> /dev/null
				crictl ps -a 1> $OUTPUT_DIR/containers/containerd/cri/containers.txt 2> /dev/null
				crictl stats --all 1> $OUTPUT_DIR/containers/containerd/cri/stats.txt 2> /dev/null
			fi
		fi
		echo "  ${COL_ENTRY}>${RESET} Collecting containerd-shim information"
		ps aux | grep -E "containerd-shim|shim.v[12]" | grep -v grep 1> $OUTPUT_DIR/containers/containerd/shim_processes.txt 2> /dev/null
		mount | grep containerd 1> $OUTPUT_DIR/containers/containerd/mounts.txt 2> /dev/null
		if [ "$EUID" -eq 0 ]; then
			ss -xlnp | grep containerd 1> $OUTPUT_DIR/containers/containerd/socket_connections.txt 2> /dev/null
		fi
	fi
	if [ -x "$(command -v ctr)" ] && [ ! -x "$(command -v containerd)" ]; then
		echo "  ${COL_ENTRY}>${RESET} Found ctr without containerd daemon - collecting available information"
		mkdir -p $OUTPUT_DIR/containers/containerd_standalone
		ctr version 1> $OUTPUT_DIR/containers/containerd_standalone/ctr_version.txt 2> /dev/null
		ctr namespace ls 1> $OUTPUT_DIR/containers/containerd_standalone/namespaces.txt 2> /dev/null
		ctr plugins ls 1> $OUTPUT_DIR/containers/containerd_standalone/plugins.txt 2> /dev/null
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
		docker events --since 24h --until now --format 'json' 2>&1 | head -100 > $OUTPUT_DIR/containers/docker_events_24h.json 2> /dev/null
		docker system info --format '{{json .}}' 1> $OUTPUT_DIR/containers/docker_info_json.txt 2> /dev/null
		docker system df 1> $OUTPUT_DIR/containers/docker_system_df.txt 2> /dev/null
		docker plugin ls 1> $OUTPUT_DIR/containers/docker_plugins.txt 2> /dev/null
		docker swarm ca 2>&1 | grep -q "This node is not a swarm manager" || {
			echo "  ${COL_ENTRY}>${RESET} Collecting Docker Swarm information"
			docker node ls 1> $OUTPUT_DIR/containers/docker_swarm_nodes.txt 2> /dev/null
			docker service ls 1> $OUTPUT_DIR/containers/docker_swarm_services.txt 2> /dev/null
			docker stack ls 1> $OUTPUT_DIR/containers/docker_swarm_stacks.txt 2> /dev/null
			docker secret ls 1> $OUTPUT_DIR/containers/docker_swarm_secrets.txt 2> /dev/null
			docker config ls 1> $OUTPUT_DIR/containers/docker_swarm_configs.txt 2> /dev/null
		}
		docker container ps --all --format "{{.ID}}" 1> $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null

		while read -r containerid; do
			if [ -n "$containerid" ]; then
				echo "=== Container: $containerid ===" >> $OUTPUT_DIR/containers/docker_container_details.txt
				echo "--- Logs (last 1000 lines) ---" >> $OUTPUT_DIR/containers/docker_container_details.txt
				docker container logs "$containerid" --tail 1000 >> $OUTPUT_DIR/containers/docker_container_details.txt 2> /dev/null
				echo "--- Inspect ---" >> $OUTPUT_DIR/containers/docker_container_details.txt
				docker inspect "$containerid" >> $OUTPUT_DIR/containers/docker_container_details.txt 2> /dev/null
				echo "--- Processes ---" >> $OUTPUT_DIR/containers/docker_container_details.txt
				docker top "$containerid" >> $OUTPUT_DIR/containers/docker_container_details.txt 2> /dev/null
				echo "--- Filesystem Diff ---" >> $OUTPUT_DIR/containers/docker_container_details.txt
				docker diff "$containerid" >> $OUTPUT_DIR/containers/docker_container_details.txt 2> /dev/null
				echo "--- Port Mappings ---" >> $OUTPUT_DIR/containers/docker_container_details.txt
				docker port "$containerid" >> $OUTPUT_DIR/containers/docker_container_details.txt 2> /dev/null
				echo "--- Resource Usage ---" >> $OUTPUT_DIR/containers/docker_container_details.txt
				docker stats "$containerid" --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" >> $OUTPUT_DIR/containers/docker_container_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/docker_container_details.txt
				docker logs "$containerid" > "$OUTPUT_DIR/containers/docker_logs_${containerid}.txt" 2> /dev/null
				docker inspect "$containerid" > "$OUTPUT_DIR/containers/docker_inspect_${containerid}.json" 2> /dev/null
				docker top "$containerid" > "$OUTPUT_DIR/containers/docker_processes_${containerid}.txt" 2> /dev/null
				docker diff "$containerid" > "$OUTPUT_DIR/containers/docker_filesystem_diff_${containerid}.txt" 2> /dev/null
			fi
		done < $OUTPUT_DIR/containers/docker_ids.txt 2> /dev/null
		docker network ls --format "{{.ID}}" | while read netid; do
			if [ -n "$netid" ]; then
				echo "=== Network: $netid ===" >> $OUTPUT_DIR/containers/docker_network_configs.txt
				docker network inspect "$netid" >> $OUTPUT_DIR/containers/docker_network_configs.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/docker_network_configs.txt
			fi
		done

		docker volume ls --format "{{.Name}}" | while read volname; do
			if [ -n "$volname" ]; then
				echo "=== Volume: $volname ===" >> $OUTPUT_DIR/containers/docker_volume_configs.txt
				docker volume inspect "$volname" >> $OUTPUT_DIR/containers/docker_volume_configs.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/docker_volume_configs.txt
			fi
		done

		docker image ls --format "{{.ID}}" --no-trunc | while read imageid; do
			if [ -n "$imageid" ]; then
				echo "=== Image: $imageid ===" >> $OUTPUT_DIR/containers/docker_image_details.txt
				docker image inspect "$imageid" >> $OUTPUT_DIR/containers/docker_image_details.txt 2> /dev/null
				docker image history "$imageid" >> $OUTPUT_DIR/containers/docker_image_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/docker_image_details.txt
			fi
		done
		
		docker image ls --filter "dangling=true" 1> $OUTPUT_DIR/containers/docker_dangling_images.txt 2> /dev/null
		docker system prune --dry-run 1> $OUTPUT_DIR/containers/docker_prune_dryrun.txt 2> /dev/null

		if [ -x "$(command -v docker-compose)" ]; then
			echo "  ${COL_ENTRY}>${RESET} Collecting Docker Compose information"
			docker-compose version 1> $OUTPUT_DIR/containers/docker_compose_version.txt 2> /dev/null
			# Find compose files in common locations
			find /home /root /opt -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "compose.yml" -o -name "compose.yaml" 2>/dev/null | head -50 > $OUTPUT_DIR/containers/docker_compose_files.txt
		fi

		echo "  ${COL_ENTRY}>${RESET} Collecting Docker configuration"
		if [ -f "/etc/docker/daemon.json" ]; then
			cp /etc/docker/daemon.json $OUTPUT_DIR/containers/docker_daemon.json 2> /dev/null
		fi
		
		if [ -d "/etc/docker" ]; then
			ls -la /etc/docker/ > $OUTPUT_DIR/containers/docker_etc_listing.txt 2> /dev/null
		fi

		if [ -x "$(command -v systemctl)" ]; then
			systemctl status docker > $OUTPUT_DIR/containers/docker_service_status.txt 2> /dev/null
			systemctl status docker.socket >> $OUTPUT_DIR/containers/docker_service_status.txt 2> /dev/null
			systemctl status containerd >> $OUTPUT_DIR/containers/docker_service_status.txt 2> /dev/null
		fi
		
		DOCKER_ROOT=$(docker info 2>/dev/null | grep "Docker Root Dir" | awk '{print $NF}')
		if [ -n "$DOCKER_ROOT" ] && [ -d "$DOCKER_ROOT" ]; then
			echo "Docker Root: $DOCKER_ROOT" > $OUTPUT_DIR/containers/docker_root_info.txt
			du -sh "$DOCKER_ROOT" >> $OUTPUT_DIR/containers/docker_root_info.txt 2> /dev/null
			ls -la "$DOCKER_ROOT" >> $OUTPUT_DIR/containers/docker_root_info.txt 2> /dev/null
		fi
		
		docker info 2>/dev/null | grep -A 10 "Registry" > $OUTPUT_DIR/containers/docker_registries.txt
		
		if [ -d "$HOME/.docker/trust" ]; then
			ls -la "$HOME/.docker/trust/" > $OUTPUT_DIR/containers/docker_trust_listing.txt 2> /dev/null
		fi
		
		docker buildx ls 2>/dev/null 1> $OUTPUT_DIR/containers/docker_buildx_list.txt
		docker buildx version 2>/dev/null 1> $OUTPUT_DIR/containers/docker_buildx_version.txt
		docker info 2>/dev/null | grep -E "Runtime|runc|containerd" > $OUTPUT_DIR/containers/docker_runtime_info.txt
		find /etc/systemd /lib/systemd /usr/lib/systemd -name "*docker*" -o -name "*container*" 2>/dev/null | grep -v "\.wants" | sort -u > $OUTPUT_DIR/containers/docker_systemd_units.txt 2> /dev/null
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
	
	# Check for Proxmox environment
	if [ -x "$(command -v pct)" ] || [ -x "$(command -v qm)" ] || [ -x "$(command -v pvesh)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting Proxmox environment information"
		mkdir -p $OUTPUT_DIR/containers/proxmox
		mkdir -p $OUTPUT_DIR/virtual/proxmox
		
		if [ -x "$(command -v pveversion)" ]; then
			pveversion --verbose 1> $OUTPUT_DIR/virtual/proxmox/pve_version.txt 2> /dev/null
		fi
		
		if [ -f /etc/pve/subscription ]; then
			cp /etc/pve/subscription $OUTPUT_DIR/virtual/proxmox/subscription.txt 2> /dev/null
		fi

		if [ -x "$(command -v pvecm)" ]; then
			pvecm status 1> $OUTPUT_DIR/virtual/proxmox/cluster_status.txt 2> /dev/null
			pvecm nodes 1> $OUTPUT_DIR/virtual/proxmox/cluster_nodes.txt 2> /dev/null
		fi
		
		if [ -x "$(command -v corosync-cfgtool)" ]; then
			corosync-cfgtool -s 1> $OUTPUT_DIR/virtual/proxmox/corosync_status.txt 2> /dev/null
		fi
		
		if [ -x "$(command -v pvesm)" ]; then
			echo "  ${COL_ENTRY}>${RESET} Collecting Proxmox storage information"
			pvesm status 1> $OUTPUT_DIR/virtual/proxmox/storage_status.txt 2> /dev/null
			pvesm list local 1> $OUTPUT_DIR/virtual/proxmox/storage_list_local.txt 2> /dev/null
			pvesm status | tail -n +2 | awk '{print $1}' | while read storage; do
				pvesm list "$storage" 1> $OUTPUT_DIR/virtual/proxmox/storage_content_${storage}.txt 2> /dev/null
			done
		fi
	
		if [ -x "$(command -v pve-firewall)" ]; then
			pve-firewall compile 1> $OUTPUT_DIR/virtual/proxmox/firewall_rules.txt 2> /dev/null
		fi

		if [ -f /etc/pve/vzdump.conf ]; then
			cp /etc/pve/vzdump.conf $OUTPUT_DIR/virtual/proxmox/vzdump_config.txt 2> /dev/null
		fi

		if [ -f /etc/pve/nodes/*/network ]; then
			cp /etc/pve/nodes/*/network $OUTPUT_DIR/virtual/proxmox/ 2> /dev/null
		fi
	fi

	if [ -x "$(command -v pct)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting Proxmox LXC container information"

		pct list 1> $OUTPUT_DIR/containers/proxmox/container_list.txt 2> /dev/null
		pct cpusets 1> $OUTPUT_DIR/containers/proxmox/cpusets.txt 2> /dev/null
		pct list | sed -e '1d' | awk '{print $1}' 1> $OUTPUT_DIR/containers/proxmox/container_ids.txt 2> /dev/null
		
		while read -r containerid; do
			echo "  ${COL_ENTRY}>${RESET} Collecting details for container $containerid"
			mkdir -p $OUTPUT_DIR/containers/proxmox/$containerid
			pct config "$containerid" 1> $OUTPUT_DIR/containers/proxmox/$containerid/config.txt 2> /dev/null
			pct status "$containerid" 1> $OUTPUT_DIR/containers/proxmox/$containerid/status.txt 2> /dev/null
			pct pending "$containerid" 1> $OUTPUT_DIR/containers/proxmox/$containerid/pending.txt 2> /dev/null
			pct listsnapshot "$containerid" 1> $OUTPUT_DIR/containers/proxmox/$containerid/snapshots.txt 2> /dev/null
			pct df "$containerid" 1> $OUTPUT_DIR/containers/proxmox/$containerid/disk_usage.txt 2> /dev/null
			pct mount "$containerid" 1> $OUTPUT_DIR/containers/proxmox/$containerid/mount_attempt.txt 2> /dev/null
			pct unmount "$containerid" 2> /dev/null
			if [ -x "$(command -v pvesh)" ]; then
				pvesh get /nodes/localhost/lxc/$containerid/rrddata 1> $OUTPUT_DIR/containers/proxmox/$containerid/resource_stats.txt 2> /dev/null
			fi
			
		done < $OUTPUT_DIR/containers/proxmox/container_ids.txt
	fi

	if [ -x "$(command -v qm)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting Proxmox VM information"
		qm list 1> $OUTPUT_DIR/virtual/proxmox/vm_list.txt 2> /dev/null
		qm list | sed -e '1d' | awk '{print $1}' 1> $OUTPUT_DIR/virtual/proxmox/vm_ids.txt 2> /dev/null
		
		while read -r vmid; do
			echo "  ${COL_ENTRY}>${RESET} Collecting details for VM $vmid"
			mkdir -p $OUTPUT_DIR/virtual/proxmox/$vmid
			qm config "$vmid" 1> $OUTPUT_DIR/virtual/proxmox/$vmid/config.txt 2> /dev/null
			qm status "$vmid" --verbose 1> $OUTPUT_DIR/virtual/proxmox/$vmid/status.txt 2> /dev/null
			qm pending "$vmid" 1> $OUTPUT_DIR/virtual/proxmox/$vmid/pending.txt 2> /dev/null
			qm listsnapshot "$vmid" 1> $OUTPUT_DIR/virtual/proxmox/$vmid/snapshots.txt 2> /dev/null
			qm cloudinit dump "$vmid" 1> $OUTPUT_DIR/virtual/proxmox/$vmid/cloudinit.txt 2> /dev/null
			qm agent "$vmid" ping 1> $OUTPUT_DIR/virtual/proxmox/$vmid/agent_status.txt 2> /dev/null
			if [ -x "$(command -v pvesh)" ]; then
				pvesh get /nodes/localhost/qemu/$vmid/rrddata 1> $OUTPUT_DIR/virtual/proxmox/$vmid/resource_stats.txt 2> /dev/null
			fi
			
		done < $OUTPUT_DIR/virtual/proxmox/vm_ids.txt
	fi

	if [ -x "$(command -v pvesh)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting Proxmox API information"
		pvesh get /nodes 1> $OUTPUT_DIR/virtual/proxmox/nodes_info.txt 2> /dev/null
		NODENAME=$(hostname)
		pvesh get /nodes/$NODENAME/status 1> $OUTPUT_DIR/virtual/proxmox/node_status.txt 2> /dev/null
		pvesh get /nodes/$NODENAME/services 1> $OUTPUT_DIR/virtual/proxmox/services_status.txt 2> /dev/null
		pvesh get /nodes/$NODENAME/tasks --limit 100 1> $OUTPUT_DIR/virtual/proxmox/tasks_history.txt 2> /dev/null
		pvesh get /storage 1> $OUTPUT_DIR/virtual/proxmox/storage_api.txt 2> /dev/null
		pvesh get /cluster/backup 1> $OUTPUT_DIR/virtual/proxmox/backup_jobs.txt 2> /dev/null 2> /dev/null
		pvesh get /cluster/replication 1> $OUTPUT_DIR/virtual/proxmox/replication_jobs.txt 2> /dev/null 2> /dev/null
		pvesh get /cluster/ha/status/current 1> $OUTPUT_DIR/virtual/proxmox/ha_status.txt 2> /dev/null 2> /dev/null
		pvesh get /access/users 1> $OUTPUT_DIR/virtual/proxmox/users.txt 2> /dev/null
		pvesh get /access/groups 1> $OUTPUT_DIR/virtual/proxmox/groups.txt 2> /dev/null
		pvesh get /access/roles 1> $OUTPUT_DIR/virtual/proxmox/roles.txt 2> /dev/null
		pvesh get /access/domains 1> $OUTPUT_DIR/virtual/proxmox/auth_domains.txt 2> /dev/null
	fi
	if [ -d /var/log/pve ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting Proxmox logs"
		mkdir -p $OUTPUT_DIR/logs/proxmox
		cp -R /var/log/pve/* $OUTPUT_DIR/logs/proxmox/ 2> /dev/null
	fi
	
	if [ -d /etc/pve ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting Proxmox configuration"
		# Note: /etc/pve is a FUSE mount, be careful with permissions
		mkdir -p $OUTPUT_DIR/virtual/proxmox/config
		
		# Safely copy readable files
		find /etc/pve -type f -readable 2>/dev/null | while read file; do
			dest_dir="$OUTPUT_DIR/virtual/proxmox/config/$(dirname "$file" | sed 's|/etc/pve||')"
			mkdir -p "$dest_dir"
			cp "$file" "$dest_dir/" 2>/dev/null
		done
	fi

	# OpenVZ legacy support (if present)
	if [ -x "$(command -v vzctl)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting OpenVZ information"
		vzctl list -a 1> $OUTPUT_DIR/containers/openvz_list.txt 2> /dev/null
		vzlist -a -o ctid,hostname,status,ip,diskspace,physpages 1> $OUTPUT_DIR/containers/openvz_detailed.txt 2> /dev/null
	fi
	
	if [ -x "$(command -v podman)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting PODMAN information"
		podman container ls --all --size 1> $OUTPUT_DIR/containers/podman_container_list.txt 2> /dev/null
		podman image ls --all 1> $OUTPUT_DIR/containers/podman_image_list.txt 2> /dev/null
		podman version 1> $OUTPUT_DIR/containers/podman_version.txt 2> /dev/null
		podman network ls 1> $OUTPUT_DIR/containers/podman_networks.txt 2> /dev/null
		podman volume ls 1> $OUTPUT_DIR/containers/podman_volumes.txt 2> /dev/null
		podman info 1> $OUTPUT_DIR/containers/podman_info.txt 2> /dev/null
		podman system info --format json 1> $OUTPUT_DIR/containers/podman_info_json.txt 2> /dev/null
		podman system df 1> $OUTPUT_DIR/containers/podman_system_df.txt 2> /dev/null
		podman pod ls --format json 1> $OUTPUT_DIR/containers/podman_pods_json.txt 2> /dev/null
		podman pod ls 1> $OUTPUT_DIR/containers/podman_pods.txt 2> /dev/null
		podman events --since 24h --format json 2>&1 | head -100 > $OUTPUT_DIR/containers/podman_events_24h.txt 2> /dev/null
		podman secret ls 1> $OUTPUT_DIR/containers/podman_secrets_list.txt 2> /dev/null
		if podman machine list &>/dev/null; then
			podman machine list 1> $OUTPUT_DIR/containers/podman_machine_list.txt 2> /dev/null
			podman machine info 1> $OUTPUT_DIR/containers/podman_machine_info.txt 2> /dev/null
		fi
		podman container ps --all --format "{{.ID}}" 1> $OUTPUT_DIR/containers/podman_container_ids.txt 2> /dev/null
		while read -r containerid; do
			if [ -n "$containerid" ]; then
				echo "=== Container: $containerid ===" >> $OUTPUT_DIR/containers/podman_container_details.txt
				echo "--- Logs (last 100 lines) ---" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman container logs "$containerid" --tail 100 >> $OUTPUT_DIR/containers/podman_container_details.txt 2> /dev/null
				echo "--- Inspect ---" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman inspect "$containerid" >> $OUTPUT_DIR/containers/podman_container_details.txt 2> /dev/null
				echo "--- Processes ---" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman top "$containerid" >> $OUTPUT_DIR/containers/podman_container_details.txt 2> /dev/null
				echo "--- Filesystem Diff ---" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman diff "$containerid" >> $OUTPUT_DIR/containers/podman_container_details.txt 2> /dev/null
				echo "--- Stats ---" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman stats "$containerid" --no-stream >> $OUTPUT_DIR/containers/podman_container_details.txt 2> /dev/null
				echo "--- Port Mappings ---" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman port "$containerid" >> $OUTPUT_DIR/containers/podman_container_details.txt 2> /dev/null
				echo "--- Health Check ---" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman healthcheck run "$containerid" >> $OUTPUT_DIR/containers/podman_container_details.txt 2> /dev/null
				echo "--- Mounts ---" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman inspect "$containerid" --format "{{json .Mounts}}" >> $OUTPUT_DIR/containers/podman_container_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/podman_container_details.txt
				podman logs "$containerid" > "$OUTPUT_DIR/containers/podman_logs_${containerid}.txt" 2> /dev/null
				podman inspect "$containerid" > "$OUTPUT_DIR/containers/podman_inspect_${containerid}.json" 2> /dev/null
			fi
		done < $OUTPUT_DIR/containers/podman_container_ids.txt 2> /dev/null

		podman network ls --format "{{.Name}}" | while read netname; do
			if [ -n "$netname" ]; then
				echo "=== Network: $netname ===" >> $OUTPUT_DIR/containers/podman_network_configs.txt
				podman network inspect "$netname" >> $OUTPUT_DIR/containers/podman_network_configs.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/podman_network_configs.txt
			fi
		done
		
		podman volume ls --format "{{.Name}}" 1> $OUTPUT_DIR/containers/podman_volume_ids.txt 2> /dev/null
		while read -r volumeid; do
			if [ -n "$volumeid" ]; then
				echo "=== Volume: $volumeid ===" >> $OUTPUT_DIR/containers/podman_volume_details.txt
				podman volume inspect "$volumeid" >> $OUTPUT_DIR/containers/podman_volume_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/podman_volume_details.txt
			fi
		done < $OUTPUT_DIR/containers/podman_volume_ids.txt 2> /dev/null

		podman image ls --format "{{.ID}}" --no-trunc | while read imageid; do
			if [ -n "$imageid" ]; then
				echo "=== Image: $imageid ===" >> $OUTPUT_DIR/containers/podman_image_details.txt
				podman image inspect "$imageid" >> $OUTPUT_DIR/containers/podman_image_details.txt 2> /dev/null
				podman image history "$imageid" >> $OUTPUT_DIR/containers/podman_image_details.txt 2> /dev/null
				podman image tree "$imageid" >> $OUTPUT_DIR/containers/podman_image_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/podman_image_details.txt
			fi
		done
		
		podman pod ls --format "{{.ID}}" | while read podid; do
			if [ -n "$podid" ]; then
				echo "=== Pod: $podid ===" >> $OUTPUT_DIR/containers/podman_pod_details.txt
				podman pod inspect "$podid" >> $OUTPUT_DIR/containers/podman_pod_details.txt 2> /dev/null
				podman pod stats "$podid" --no-stream >> $OUTPUT_DIR/containers/podman_pod_details.txt 2> /dev/null
				podman pod top "$podid" >> $OUTPUT_DIR/containers/podman_pod_details.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/podman_pod_details.txt
			fi
		done
		
		podman image ls --filter dangling=true 1> $OUTPUT_DIR/containers/podman_dangling_images.txt 2> /dev/null
		podman system prune --dry-run 1> $OUTPUT_DIR/containers/podman_prune_dryrun.txt 2> /dev/null
		
		if [ -d "$HOME/.config/containers" ]; then
			echo "  ${COL_ENTRY}>${RESET} Collecting Podman configuration"
			ls -la "$HOME/.config/containers/" > $OUTPUT_DIR/containers/podman_config_listing.txt 2> /dev/null
			# Copy non-sensitive configs
			for conf in storage.conf containers.conf registries.conf; do
				if [ -f "$HOME/.config/containers/$conf" ]; then
					cp "$HOME/.config/containers/$conf" "$OUTPUT_DIR/containers/podman_$conf" 2> /dev/null
				fi
			done
		fi
		
		if [ -d "/etc/containers" ]; then
			ls -la /etc/containers/ > $OUTPUT_DIR/containers/podman_etc_config_listing.txt 2> /dev/null
			for conf in storage.conf containers.conf registries.conf policy.json; do
				if [ -f "/etc/containers/$conf" ]; then
					cp "/etc/containers/$conf" "$OUTPUT_DIR/containers/podman_etc_$conf" 2> /dev/null
				fi
			done
		fi
		
		if [ "$EUID" -ne 0 ]; then
			echo "Running as rootless podman" > $OUTPUT_DIR/containers/podman_rootless.txt
			podman unshare cat /proc/self/uid_map >> $OUTPUT_DIR/containers/podman_rootless.txt 2> /dev/null
			podman unshare cat /proc/self/gid_map >> $OUTPUT_DIR/containers/podman_rootless.txt 2> /dev/null
		fi
		
		if [ -d "$HOME/.config/systemd/user" ]; then
			find "$HOME/.config/systemd/user" -name "*podman*" -o -name "*container*" 2>/dev/null > $OUTPUT_DIR/containers/podman_systemd_units.txt
		fi
	
		podman container ls --format "{{.Names}}" | while read cname; do
			if [ -n "$cname" ]; then
				echo "=== Container: $cname ===" >> $OUTPUT_DIR/containers/podman_systemd_generate.txt
				podman generate systemd "$cname" >> $OUTPUT_DIR/containers/podman_systemd_generate.txt 2> /dev/null
				echo "" >> $OUTPUT_DIR/containers/podman_systemd_generate.txt
			fi
		done
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
