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
# Copyright (C)  Jerzy 'Yuri' Kramarz (op7ic) 
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
VERSION="2.0"
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

echo "  ${COL_ENTRY}>${RESET} Kernel integrity and taint checks"
mkdir -p $OUTPUT_DIR/general/kernel_integrity 2> /dev/null

# Linux kernel taint check
if [ -f /proc/sys/kernel/tainted ]
then
    # Get the taint value
    TAINT_VALUE=$(cat /proc/sys/kernel/tainted 2> /dev/null)
    echo $TAINT_VALUE > $OUTPUT_DIR/general/kernel_integrity/tainted_kernel_value.txt
    
    # Decode taint flags with descriptions
    echo "Kernel Taint Analysis" > $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
    echo "===================" >> $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
    echo "Taint value: $TAINT_VALUE" >> $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
    echo "" >> $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
    
    if [ "$TAINT_VALUE" = "0" ]
    then
        echo "Kernel is NOT tainted" >> $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
    else
        echo "Kernel IS tainted with the following flags:" >> $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
        echo "" >> $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
        
        # Taint flag descriptions
        echo "Bit Value Meaning" > $OUTPUT_DIR/general/kernel_integrity/taint_flags.txt
        echo "--- ----- -------" >> $OUTPUT_DIR/general/kernel_integrity/taint_flags.txt
        
        # Define taint flags (up to bit 18 as of Linux 5.x)
        i=0
        for FLAG in \
            "0:G:Proprietary module loaded" \
            "1:F:Module forced load" \
            "2:S:SMP kernel on non-SMP processor" \
            "3:R:Module force unloaded" \
            "4:M:Machine check exception" \
            "5:B:Bad page referenced" \
            "6:U:User requested taint" \
            "7:D:Kernel died recently (OOPS/BUG)" \
            "8:A:ACPI table overridden" \
            "9:W:Warning issued by kernel" \
            "10:C:Staging driver loaded" \
            "11:I:Platform firmware bug workaround" \
            "12:O:Out-of-tree module loaded" \
            "13:E:Unsigned module loaded" \
            "14:L:Soft lockup occurred" \
            "15:K:Kernel live patched" \
            "16:X:Auxiliary taint (distro-specific)" \
            "17:T:Kernel built with struct randomization"
        do
            BIT_NUM=$(echo $FLAG | cut -d: -f1)
            FLAG_CHAR=$(echo $FLAG | cut -d: -f2)
            FLAG_DESC=$(echo $FLAG | cut -d: -f3)
            
            # Check if bit is set
            if [ $(((TAINT_VALUE >> BIT_NUM) & 1)) -eq 1 ]
            then
                echo "$BIT_NUM   $FLAG_CHAR     $FLAG_DESC" >> $OUTPUT_DIR/general/kernel_integrity/taint_flags.txt
                echo "  [$FLAG_CHAR] $FLAG_DESC" >> $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
            fi
            
            i=$((i + 1))
        done
    fi
    
    # Original bitmap for compatibility
    echo "Taint bitmap (bit position : value):" >> $OUTPUT_DIR/general/kernel_integrity/taint_analysis.txt
    for i in $(seq 0 17); do 
        BIT_VAL=$(((TAINT_VALUE >> i) & 1))
        echo "$i:$BIT_VAL" >> $OUTPUT_DIR/general/kernel_integrity/taint_bitmap.txt
    done
fi

echo "  ${COL_ENTRY}>${RESET} SSH settings"
sshd -T 1> $OUTPUT_DIR/general/sshd-t.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Generating file timeline in multiple formats"
mkdir -p $OUTPUT_DIR/general/timeline 2> /dev/null
TIMELINE_START=$(date)
echo "Timeline generation started: $TIMELINE_START" > $OUTPUT_DIR/general/timeline/timeline_info.txt
STAT_TYPE="unknown"
STAT_CMD=""
if stat --version 2> /dev/null | grep -q "GNU coreutils"
then
    STAT_TYPE="gnu"
    STAT_CMD="stat"
elif stat -f "%N" / >/dev/null 2>&1
then
    STAT_TYPE="bsd"
    STAT_CMD="stat"
elif [ -x /usr/bin/stat ] && /usr/bin/stat --version 2>&1 | grep -q "stat"
then
    STAT_TYPE="solaris"
    STAT_CMD="/usr/bin/stat"
fi

echo "Stat type detected: $STAT_TYPE" >> $OUTPUT_DIR/general/timeline/timeline_info.txt
# Standard bodyfile format (Sleuthkit 3.0+ format)
# MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
echo "# Sleuthkit 3.0+ bodyfile format" > $OUTPUT_DIR/general/timeline/bodyfile.txt
echo "# MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime" >> $OUTPUT_DIR/general/timeline/bodyfile.txt

# CSV format with headers
echo "Inode,Hard Link Count,Full Path,Last Access,Last Modification,Last Status Change,File Creation,User,Group,File Permissions,File Size(bytes),File Type,MD5" > $OUTPUT_DIR/general/timeline/timeline.csv

# Platform-specific timeline generation
case $PLATFORM in
    "linux"|"android"|"generic")
        # Generate bodyfile format
        find / -xdev -type f -o -type d -o -type l 2> /dev/null | while read filepath
        do
            # Skip if file doesn't exist (race condition)
            [ -e "$filepath" ] || continue
            # Get file stats
            if [ "$STAT_TYPE" = "gnu" ]
            then
                # GNU stat with all needed fields
                stat -c "0|%n|%i|%A|%u|%g|%s|%X|%Y|%Z|%W" "$filepath" 2> /dev/null >> $OUTPUT_DIR/general/timeline/bodyfile.txt
                # CSV format with human-readable times
                stat -c "%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s,%F" "$filepath" 2> /dev/null | sed 's/|/,/g' >> $OUTPUT_DIR/general/timeline/timeline.csv
            fi
        done
        
        # Alternative method using find -printf if stat fails
        if [ ! -s "$OUTPUT_DIR/general/timeline/bodyfile.txt" ] || [ $(wc -l < $OUTPUT_DIR/general/timeline/bodyfile.txt) -lt 10 ]
        then
            find / -xdev \( -type f -o -type d -o -type l \) -printf "0|%p|%i|%M|%u|%g|%s|%A@|%T@|%C@|0\n" 2> /dev/null >> $OUTPUT_DIR/general/timeline/bodyfile_find.txt
        fi
        ;;
        
    "mac")
        # macOS uses BSD stat with different format
        find / -xdev -type f -o -type d -o -type l 2> /dev/null | while read filepath
        do
            [ -e "$filepath" ] || continue  
            # BSD stat format for bodyfile
            # Get numeric permissions, times as epoch
            INODE=$(stat -f "%i" "$filepath" 2> /dev/null)
            MODE=$(stat -f "%Mp%Lp" "$filepath" 2> /dev/null)
            UID=$(stat -f "%u" "$filepath" 2> /dev/null)
            GID=$(stat -f "%g" "$filepath" 2> /dev/null)
            SIZE=$(stat -f "%z" "$filepath" 2> /dev/null)
            ATIME=$(stat -f "%a" "$filepath" 2> /dev/null)
            MTIME=$(stat -f "%m" "$filepath" 2> /dev/null)
            CTIME=$(stat -f "%c" "$filepath" 2> /dev/null)
            BTIME=$(stat -f "%B" "$filepath" 2> /dev/null)  # Birth time on macOS
            echo "0|$filepath|$INODE|$MODE|$UID|$GID|$SIZE|$ATIME|$MTIME|$CTIME|$BTIME" >> $OUTPUT_DIR/general/timeline/bodyfile.txt
            # Human readable format
            stat -f "%i,%l,%N,%Sa,%Sm,%Sc,%SB,%Su,%Sg,%Sp,%z,%HT" "$filepath" 2> /dev/null >> $OUTPUT_DIR/general/timeline/timeline.csv
        done
        find / -xdev -print0 2> /dev/null | xargs -0 stat -L > $OUTPUT_DIR/general/timeline/timeline_mac_native.txt 2> /dev/null
        ;;
    "solaris")
        if [ "$STAT_TYPE" = "gnu" ]
        then
            find / -xdev -type f -o -type d -o -type l 2> /dev/null | while read filepath
            do
                [ -e "$filepath" ] || continue
                stat -c "0|%n|%i|%A|%u|%g|%s|%X|%Y|%Z|%W" "$filepath" 2> /dev/null >> $OUTPUT_DIR/general/timeline/bodyfile.txt
                stat -c "%i,%h,%n,%x,%y,%z,%w,%U,%G,%A,%s,%F" "$filepath" 2> /dev/null >> $OUTPUT_DIR/general/timeline/timeline.csv
            done
        else
            # Fallback to ls and perl for Solaris
            echo "  ${COL_ENTRY}>${RESET} Using perl method for Solaris"
            find / -xdev 2> /dev/null | perl -ne 'chomp; 
                @s=stat($_); 
                next unless @s; 
                ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks)=@s;
                $mode_str = sprintf("%04o", $mode & 07777);
                print "0|$_|$ino|$mode_str|$uid|$gid|$size|$atime|$mtime|$ctime|0\n";
            ' >> $OUTPUT_DIR/general/timeline/bodyfile.txt 2> /dev/null
        fi
        ;;
    "aix")
        # AIX using perl method (most reliable)
        find / -xdev 2> /dev/null | perl -ne 'chomp;
            $_ =~ s/\x0a//g; $_ =~ s/\x0d//g;
            @s = stat($_);
            next unless @s;
            ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = @s;
            # Bodyfile format
            $mode_str = sprintf("%04o", $mode & 07777);
            print "0|$_|$ino|$mode_str|$uid|$gid|$size|$atime|$mtime|$ctime|0\n";
        ' > $OUTPUT_DIR/general/timeline/bodyfile.txt 2> /dev/null
        echo "device number,inode,file name,nlink,uid,gid,rdev,size,access time,modified time,inode change time,io size,block size" > $OUTPUT_DIR/general/timeline/timeline.csv
        find / -xdev 2> /dev/null | perl -n -e '$_ =~ s/\x0a//g; $_ =~ s/\x0d//g;print $_ . "," . join(",", stat($_)) . "\n";' >> $OUTPUT_DIR/general/timeline/timeline.csv 2> /dev/null
        ;;
    *)
        if command -v stat >/dev/null 2>&1
        then
            find / -xdev -type f -o -type d -o -type l 2> /dev/null | while read filepath
            do
                [ -e "$filepath" ] || continue
                stat -c "0|%n|%i|%A|%u|%g|%s|%X|%Y|%Z|%W" "$filepath" 2> /dev/null >> $OUTPUT_DIR/general/timeline/bodyfile.txt || \
                stat "$filepath" >> $OUTPUT_DIR/general/timeline/timeline_native.txt 2> /dev/null
            done
        fi
        ;;
esac

# Generate timeline for specific forensically interesting directories
echo "  ${COL_ENTRY}>${RESET} Generating focused timelines"
# Recently modified files (last 14 days)
echo "# Recently modified files (last 14 days)" > $OUTPUT_DIR/general/timeline/recent_files.txt
find / -xdev -type f -mtime -14 -ls 2> /dev/null >> $OUTPUT_DIR/general/timeline/recent_files.txt
# Recently accessed files (last 14 days)  
echo "# Recently accessed files (last 14 days)" > $OUTPUT_DIR/general/timeline/recent_accessed.txt
find / -xdev -type f -atime -14 -ls 2> /dev/null >> $OUTPUT_DIR/general/timeline/recent_accessed.txt
# SUID/SGID files timeline
echo "# SUID/SGID files" > $OUTPUT_DIR/general/timeline/suid_sgid_timeline.txt
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2> /dev/null >> $OUTPUT_DIR/general/timeline/suid_sgid_timeline.txt
# Timeline for critical directories
for dir in /etc /var/log /root /tmp /var/tmp /home /opt
do
    if [ -d "$dir" ]
    then
        echo "  ${COL_ENTRY}>${RESET} Timeline for $dir"
        DIR_NAME=$(echo $dir | tr '/' '_' | sed 's/^_//')
        # Quick timeline for critical directories
        find "$dir" -xdev -type f -ls 2> /dev/null | \
            awk '{print $3" "$11" "$7" "$8" "$9" "$10" "$NF}' | \
            sort -k4,5 > "$OUTPUT_DIR/general/timeline/timeline_${DIR_NAME}.txt" 2> /dev/null
    fi
done

# Count total files
TOTAL_FILES=$(wc -l < $OUTPUT_DIR/general/timeline/bodyfile.txt 2> /dev/null || echo 0)
# Find files modified in last 24 hours
if [ "$PLATFORM" != "aix" ]
then
    RECENT_24H=$(find / -xdev -type f -mtime -1 2> /dev/null | wc -l)
else
    RECENT_24H="N/A"
fi

# Create summary
echo "Timeline Generation Summary" > $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "==========================" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "Platform: $PLATFORM" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "Stat type used: $STAT_TYPE" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "Start time: $TIMELINE_START" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "End time: $(date)" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "Statistics:" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "Total files in timeline: $TOTAL_FILES" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "Files modified in last 24h: $RECENT_24H" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "Files generated:" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "- bodyfile.txt: Sleuthkit 3.0+ bodyfile format" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "- timeline.csv: CSV format with headers" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "- recent_*.txt: Recently modified/accessed files" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt
echo "- timeline_*.txt: Per-directory timelines" >> $OUTPUT_DIR/general/timeline/TIMELINE_SUMMARY.txt

if command -v perl >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/general/timeline/bodyfile.txt" ]
then
    echo "  ${COL_ENTRY}>${RESET} Converting to mactime format"
    # Simple mactime conversion (without the actual mactime tool)
    perl -ne '
        chomp;
        next if /^#/;
        @f = split /\|/;
        next unless @f >= 11;
        ($md5,$name,$inode,$mode,$uid,$gid,$size,$atime,$mtime,$ctime,$crtime) = @f;
        print "NOTE: This is a simplified mactime format\n" if $. == 1;
        print scalar(localtime($mtime)) . " | m | $mode | $uid | $gid | $size | $name\n" if $mtime > 0;
    ' < $OUTPUT_DIR/general/timeline/bodyfile.txt > $OUTPUT_DIR/general/timeline/mactime_mtime.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Capability Files"
if [ -x "$(command -v getcap)" ]; then
    getcap -r / 2>/dev/null > $OUTPUT_DIR/general/file_capabilities.txt
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

echo "  ${COL_ENTRY}>${RESET} Boot and startup information"
mkdir $OUTPUT_DIR/boot_startup 2> /dev/null

# Boot logs collection
mkdir $OUTPUT_DIR/boot_startup/boot_logs 2> /dev/null

if [ $PLATFORM = "linux" -o $PLATFORM = "generic" ]
then
    # SystemD boot logs (newer systems)
    if [ -x /usr/bin/journalctl ]; then
        journalctl -b 0 1> $OUTPUT_DIR/boot_startup/boot_logs/journalctl-current-boot.txt 2> /dev/null
        journalctl -b -1 1> $OUTPUT_DIR/boot_startup/boot_logs/journalctl-previous-boot.txt 2> /dev/null
        journalctl --list-boots 1> $OUTPUT_DIR/boot_startup/boot_logs/journalctl-boot-list.txt 2> /dev/null
        # Get boot process timing
        systemd-analyze 1> $OUTPUT_DIR/boot_startup/boot_logs/systemd-analyze.txt 2> /dev/null
        systemd-analyze blame 1> $OUTPUT_DIR/boot_startup/boot_logs/systemd-analyze-blame.txt 2> /dev/null
        systemd-analyze critical-chain 1> $OUTPUT_DIR/boot_startup/boot_logs/systemd-analyze-critical-chain.txt 2> /dev/null
    fi
    
    # Traditional boot logs
    if [ -f /var/log/boot.log ]; then
        cp /var/log/boot.log $OUTPUT_DIR/boot_startup/boot_logs/ 2> /dev/null
    fi
    if [ -f /var/log/boot ]; then
        cp /var/log/boot $OUTPUT_DIR/boot_startup/boot_logs/boot 2> /dev/null
    fi
    # Older systems might have boot.msg
    if [ -f /var/log/boot.msg ]; then
        cp /var/log/boot.msg $OUTPUT_DIR/boot_startup/boot_logs/ 2> /dev/null
    fi
    
    # Kernel ring buffer
    dmesg 1> $OUTPUT_DIR/boot_startup/boot_logs/dmesg.txt 2> /dev/null
    if [ -f /var/log/dmesg ]; then
        cp /var/log/dmesg $OUTPUT_DIR/boot_startup/boot_logs/dmesg.log 2> /dev/null
    fi
    
    # GRUB/bootloader logs
    if [ -d /boot/grub ]; then
        ls -la /boot/grub/ 1> $OUTPUT_DIR/boot_startup/boot_logs/grub-directory.txt 2> /dev/null
        if [ -f /boot/grub/grub.cfg ]; then
            cp /boot/grub/grub.cfg $OUTPUT_DIR/boot_startup/boot_logs/ 2> /dev/null
        fi
        if [ -f /boot/grub/grub.conf ]; then
            cp /boot/grub/grub.conf $OUTPUT_DIR/boot_startup/boot_logs/ 2> /dev/null
        fi
    fi
    if [ -d /boot/grub2 ]; then
        ls -la /boot/grub2/ 1> $OUTPUT_DIR/boot_startup/boot_logs/grub2-directory.txt 2> /dev/null
        if [ -f /boot/grub2/grub.cfg ]; then
            cp /boot/grub2/grub.cfg $OUTPUT_DIR/boot_startup/boot_logs/grub2.cfg 2> /dev/null
        fi
    fi
    
elif [ $PLATFORM = "solaris" ]
then
    # Solaris boot logs
    if [ -f /var/adm/messages ]; then
        grep -i boot /var/adm/messages | tail -500 1> $OUTPUT_DIR/boot_startup/boot_logs/boot-messages.txt 2> /dev/null
    fi
    # Service Management Facility logs
    svcs -x 1> $OUTPUT_DIR/boot_startup/boot_logs/svcs-failed-services.txt 2> /dev/null
    if [ -d /var/svc/log ]; then
        ls -la /var/svc/log/ 1> $OUTPUT_DIR/boot_startup/boot_logs/svc-logs-list.txt 2> /dev/null
        # Copy recent service logs
        find /var/svc/log -name "*.log" -mtime -7 -exec cp {} $OUTPUT_DIR/boot_startup/boot_logs/ \; 2> /dev/null
    fi
    # Boot archive
    bootadm list-archive 1> $OUTPUT_DIR/boot_startup/boot_logs/bootadm-list-archive.txt 2> /dev/null
    
elif [ $PLATFORM = "aix" ]
then
    # AIX boot logs
    alog -o -t boot 1> $OUTPUT_DIR/boot_startup/boot_logs/alog-boot.txt 2> /dev/null
    alog -o -t bosinst 1> $OUTPUT_DIR/boot_startup/boot_logs/alog-bosinst.txt 2> /dev/null
    # Boot list
    bootlist -m normal -o 1> $OUTPUT_DIR/boot_startup/boot_logs/bootlist-normal.txt 2> /dev/null
    bootlist -m service -o 1> $OUTPUT_DIR/boot_startup/boot_logs/bootlist-service.txt 2> /dev/null
    # Error report
    errpt | head -100 1> $OUTPUT_DIR/boot_startup/boot_logs/errpt-recent.txt 2> /dev/null
    
elif [ $PLATFORM = "mac" ]
then
    # macOS boot logs
    log show --predicate 'process == "kernel"' --last boot 1> $OUTPUT_DIR/boot_startup/boot_logs/kernel-boot-log.txt 2> /dev/null
    log show --predicate 'eventMessage contains "boot"' --last 1d 1> $OUTPUT_DIR/boot_startup/boot_logs/boot-events-1day.txt 2> /dev/null
    # System logs
    if [ -f /var/log/system.log ]; then
        grep -i boot /var/log/system.log | 1> $OUTPUT_DIR/boot_startup/boot_logs/system-boot-logs.txt 2> /dev/null
    fi
    # Boot plist
    if [ -f /Library/Preferences/SystemConfiguration/com.apple.Boot.plist ]; then
        cp /Library/Preferences/SystemConfiguration/com.apple.Boot.plist $OUTPUT_DIR/boot_startup/boot_logs/ 2> /dev/null
    fi
    
elif [ $PLATFORM = "hpux" ]
then
    # HP-UX boot logs
    if [ -f /var/adm/syslog/syslog.log ]; then
        grep -i boot /var/adm/syslog/syslog.log | tail -500 1> $OUTPUT_DIR/boot_startup/boot_logs/syslog-boot.txt 2> /dev/null
    fi
    # Show boot messages
    dmesg 1> $OUTPUT_DIR/boot_startup/boot_logs/dmesg.txt 2> /dev/null
    
elif [ $PLATFORM = "android" ]
then
    # Android boot logs
    logcat -b events -d | grep -i boot 1> $OUTPUT_DIR/boot_startup/boot_logs/logcat-boot-events.txt 2> /dev/null
    # Boot properties
    getprop | grep -E "boot|init" 1> $OUTPUT_DIR/boot_startup/boot_logs/boot-properties.txt 2> /dev/null
    # Kernel logs
    if [ -f /proc/last_kmsg ]; then
        cp /proc/last_kmsg $OUTPUT_DIR/boot_startup/boot_logs/ 2> /dev/null
    fi
fi

# Init system detection and collection
mkdir $OUTPUT_DIR/boot_startup/init_system 2> /dev/null
INIT_SYSTEM="unknown"
if [ -d /run/systemd/system ]; then
    INIT_SYSTEM="systemd"
elif [ -f /sbin/upstart-udev-bridge ]; then
    INIT_SYSTEM="upstart"
elif [ -f /etc/inittab ]; then
    INIT_SYSTEM="sysvinit"
elif [ $PLATFORM = "mac" ]; then
    INIT_SYSTEM="launchd"
elif [ $PLATFORM = "solaris" ]; then
    INIT_SYSTEM="smf"
elif [ $PLATFORM = "aix" ]; then
    INIT_SYSTEM="src"
fi
echo "Init System: $INIT_SYSTEM" > $OUTPUT_DIR/boot_startup/init_system/detected.txt

if [ "$INIT_SYSTEM" = "systemd" ]; then
    # SystemD units
    systemctl list-unit-files 1> $OUTPUT_DIR/boot_startup/init_system/systemd-unit-files.txt 2> /dev/null
    systemctl list-units 1> $OUTPUT_DIR/boot_startup/init_system/systemd-units.txt 2> /dev/null
    systemctl list-dependencies 1> $OUTPUT_DIR/boot_startup/init_system/systemd-dependencies.txt 2> /dev/null
    # Default target
    systemctl get-default 1> $OUTPUT_DIR/boot_startup/init_system/systemd-default-target.txt 2> /dev/null
    # Failed units
    systemctl --failed 1> $OUTPUT_DIR/boot_startup/init_system/systemd-failed.txt 2> /dev/null
    # Copy unit files
    mkdir $OUTPUT_DIR/boot_startup/init_system/systemd_units 2> /dev/null
    for unit_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system
    do
        if [ -d "$unit_dir" ]; then
            find "$unit_dir" -name "*.service" -o -name "*.target" | head -50 | while read unit_file
            do
                cp "$unit_file" $OUTPUT_DIR/boot_startup/init_system/systemd_units/ 2> /dev/null
            done
        fi
    done
    
elif [ "$INIT_SYSTEM" = "sysvinit" ] || [ "$INIT_SYSTEM" = "unknown" ]; then
    # inittab
    if [ -f /etc/inittab ]; then
        cp /etc/inittab $OUTPUT_DIR/boot_startup/init_system/ 2> /dev/null
    fi
    # RC scripts
    mkdir $OUTPUT_DIR/boot_startup/init_system/rc_scripts 2> /dev/null
    for rc_dir in /etc/rc.d /etc/init.d /etc/rc.d/init.d
    do
        if [ -d "$rc_dir" ]; then
            ls -la "$rc_dir" 1> $OUTPUT_DIR/boot_startup/init_system/rc_scripts/`basename $rc_dir`-listing.txt 2> /dev/null
            # Copy key scripts
            for script in S* K* rc rc.local rc.sysinit
            do
                if [ -f "$rc_dir/$script" ]; then
                    cp "$rc_dir/$script" $OUTPUT_DIR/boot_startup/init_system/rc_scripts/ 2> /dev/null
                fi
            done
        fi
    done
    # Runlevel symlinks
    for level in 0 1 2 3 4 5 6 S
    do
        if [ -d /etc/rc${level}.d ]; then
            ls -la /etc/rc${level}.d/ 1> $OUTPUT_DIR/boot_startup/init_system/rc${level}.d-listing.txt 2> /dev/null
        elif [ -d /etc/rc.d/rc${level}.d ]; then
            ls -la /etc/rc.d/rc${level}.d/ 1> $OUTPUT_DIR/boot_startup/init_system/rc${level}.d-listing.txt 2> /dev/null
        fi
    done
    # chkconfig/update-rc.d info
    if [ -x /sbin/chkconfig ]; then
        chkconfig --list 1> $OUTPUT_DIR/boot_startup/init_system/chkconfig-list.txt 2> /dev/null
    fi
    if [ -x /usr/sbin/update-rc.d ]; then
        ls -la /etc/rc*.d/ 1> $OUTPUT_DIR/boot_startup/init_system/update-rc.d-status.txt 2> /dev/null
    fi
    
elif [ "$INIT_SYSTEM" = "upstart" ]; then
    # Upstart jobs
    if [ -d /etc/init ]; then
        mkdir $OUTPUT_DIR/boot_startup/init_system/upstart_jobs 2> /dev/null
        cp /etc/init/*.conf $OUTPUT_DIR/boot_startup/init_system/upstart_jobs/ 2> /dev/null
    fi
    # List jobs
    if [ -x /sbin/initctl ]; then
        initctl list 1> $OUTPUT_DIR/boot_startup/init_system/upstart-jobs-list.txt 2> /dev/null
    fi
fi

# Common startup files across platforms
mkdir $OUTPUT_DIR/boot_startup/startup_files 2> /dev/null

# RC files
for rc_file in /etc/rc.local /etc/rc.common /etc/rc /etc/rc.conf /etc/rc.config
do
    if [ -f "$rc_file" ]; then
        cp "$rc_file" $OUTPUT_DIR/boot_startup/startup_files/ 2> /dev/null
    fi
done

# Profile files (system-wide)
for profile in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/zsh/zshrc /etc/csh.cshrc /etc/csh.login
do
    if [ -f "$profile" ]; then
        cp "$profile" $OUTPUT_DIR/boot_startup/startup_files/ 2> /dev/null
    fi
done

# Environment files
if [ -d /etc/profile.d ]; then
    mkdir $OUTPUT_DIR/boot_startup/startup_files/profile.d 2> /dev/null
    cp /etc/profile.d/* $OUTPUT_DIR/boot_startup/startup_files/profile.d/ 2> /dev/null
fi
if [ -d /etc/env.d ]; then
    mkdir $OUTPUT_DIR/boot_startup/startup_files/env.d 2> /dev/null
    cp /etc/env.d/* $OUTPUT_DIR/boot_startup/startup_files/env.d/ 2> /dev/null
fi

# Message of the day
for motd in /etc/motd /etc/motd.tail /etc/issue /etc/issue.net
do
    if [ -f "$motd" ]; then
        cp "$motd" $OUTPUT_DIR/boot_startup/startup_files/ 2> /dev/null
    fi
done

# Boot configuration files
mkdir $OUTPUT_DIR/boot_startup/boot_config 2> /dev/null

# Kernel parameters
if [ -f /proc/cmdline ]; then
    cp /proc/cmdline $OUTPUT_DIR/boot_startup/boot_config/ 2> /dev/null
fi

# Boot loader configs
for bootcfg in /etc/lilo.conf /boot/grub/menu.lst /etc/grub.conf /etc/default/grub /etc/yaboot.conf /boot/loader.conf
do
    if [ -f "$bootcfg" ]; then
        cp "$bootcfg" $OUTPUT_DIR/boot_startup/boot_config/ 2> /dev/null
    fi
done

# EFI boot entries
if [ -x /usr/sbin/efibootmgr ]; then
    efibootmgr -v 1> $OUTPUT_DIR/boot_startup/boot_config/efibootmgr.txt 2> /dev/null
fi

# Platform specific startup
if [ $PLATFORM = "mac" ]; then
    # LaunchDaemons and LaunchAgents
    mkdir $OUTPUT_DIR/boot_startup/startup_files/launch_items 2> /dev/null
    for launch_dir in /System/Library/LaunchDaemons /Library/LaunchDaemons /System/Library/LaunchAgents /Library/LaunchAgents
    do
        if [ -d "$launch_dir" ]; then
            ls -la "$launch_dir" 1> $OUTPUT_DIR/boot_startup/startup_files/launch_items/`basename $launch_dir`-listing.txt 2> /dev/null
        fi
    done
    # StartupItems (legacy)
    for startup_dir in /System/Library/StartupItems /Library/StartupItems
    do
        if [ -d "$startup_dir" ]; then
            ls -la "$startup_dir" 1> $OUTPUT_DIR/boot_startup/startup_files/`basename $startup_dir`-listing.txt 2> /dev/null
        fi
    done
    
elif [ $PLATFORM = "solaris" ]; then
    # SMF manifests
    if [ -d /var/svc/manifest ]; then
        find /var/svc/manifest -name "*.xml" | head -50 > $OUTPUT_DIR/boot_startup/startup_files/smf-manifests.txt 2> /dev/null
    fi
    # Boot properties
    if [ -x /usr/sbin/eeprom ]; then
        eeprom 1> $OUTPUT_DIR/boot_startup/boot_config/eeprom.txt 2> /dev/null
    fi
    
elif [ $PLATFORM = "aix" ]; then
    # Inittab entries
    lsitab -a 1> $OUTPUT_DIR/boot_startup/startup_files/lsitab.txt 2> /dev/null
    # RC scripts
    if [ -f /etc/rc ]; then
        cp /etc/rc $OUTPUT_DIR/boot_startup/startup_files/ 2> /dev/null
    fi
fi

if [ -x /sbin/runlevel ]; then
    echo "Current Runlevel: `runlevel` 2> /dev/null" >> $OUTPUT_DIR/boot_startup/summary.txt 2> /dev/null
elif [ -x /usr/bin/systemctl ]; then
    echo "Current Target: `systemctl get-default 2> /dev/null`" >> $OUTPUT_DIR/boot_startup/summary.txt 2> /dev/null
fi

if [ -x /usr/bin/uptime ]; then
    echo "System Uptime: `uptime`" >> $OUTPUT_DIR/boot_startup/summary.txt 2> /dev/null
fi
if [ -x /usr/bin/who ]; then
    who -b 1>> $OUTPUT_DIR/boot_startup/summary.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} Storage Info"
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
lsof 2> /dev/null | grep -E "(deleted|DEL)" > $OUTPUT_DIR/process_info/deleted_but_running.txt 2>/dev/null
ls -la /proc/*/exe 2>/dev/null | grep deleted > $OUTPUT_DIR/process_info/deleted_executables.txt


# Enhanced process information collection
echo "  ${COL_ENTRY}>${RESET} Enhanced process information"
mkdir -p $OUTPUT_DIR/process_info/maps 2> /dev/null
mkdir -p $OUTPUT_DIR/process_info/limits 2> /dev/null
mkdir -p $OUTPUT_DIR/process_info/environ 2> /dev/null
mkdir -p $OUTPUT_DIR/process_info/status 2> /dev/null
mkdir -p $OUTPUT_DIR/process_info/stack 2> /dev/null
mkdir -p $OUTPUT_DIR/process_info/cmdline 2> /dev/null
mkdir -p $OUTPUT_DIR/process_info/namespaces 2> /dev/null
mkdir -p $OUTPUT_DIR/process_info/cgroup 2> /dev/null

# Collect enhanced process data for each PID
for pid in /proc/[0-9]*; do
    PID_NUM=$(basename $pid)
    # Memory maps and detailed memory info
	if [ -r "$pid/maps" ]; then
		cat $pid/maps > $OUTPUT_DIR/process_info/maps/maps_${PID_NUM}.txt 2> /dev/null
	fi
	if [ -r "$pid/smaps" ]; then
		cat $pid/smaps > $OUTPUT_DIR/process_info/maps/smaps_${PID_NUM}.txt 2> /dev/null
	fi
    # Resource limits
	if [ -r "$pid/limits" ]; then
		cat $pid/limits > $OUTPUT_DIR/process_info/limits/limits_${PID_NUM}.txt 2> /dev/null
	fi
    # Environment variables (make readable)
	if [ -r "$pid/environ" ]; then
		cat $pid/environ | tr '\0' '\n' > $OUTPUT_DIR/process_info/environ/environ_${PID_NUM}.txt 2> /dev/null
	fi
    # Detailed file descriptors
	if [ -r "$pid/fd" ]; then
		ls -la $pid/fd > $OUTPUT_DIR/process_info/fd_detailed_${PID_NUM}.txt 2> /dev/null
	fi
    # Process status with all details
	if [ -r "$pid/status" ]; then
		cat $pid/status > $OUTPUT_DIR/process_info/status/status_${PID_NUM}.txt 2> /dev/null
	fi
    # Stack trace (Linux 2.6.29+)
	if [ -r "$pid/stack" ]; then
		cat $pid/stack > $OUTPUT_DIR/process_info/stack/stack_${PID_NUM}.txt 2> /dev/null
	fi
    # Command line (readable format)
	if [ -r "$pid/cmdline" ]; then
		tr '\0' ' ' < $pid/cmdline > $OUTPUT_DIR/process_info/cmdline/cmdline_${PID_NUM}.txt 2> /dev/null
		echo "" >> $OUTPUT_DIR/process_info/cmdline/cmdline_${PID_NUM}.txt 2> /dev/null
	fi
    # Namespace information (Linux)
    if [ -d "$pid/ns" ]; then
        ls -la $pid/ns/ > $OUTPUT_DIR/process_info/namespaces/ns_${PID_NUM}.txt 2> /dev/null
    fi
    # Cgroup information
	if [ -r "$pid/cgroup" ]; then
		cat $pid/cgroup > $OUTPUT_DIR/process_info/cgroup/cgroup_${PID_NUM}.txt 2> /dev/null
	fi
done

if [ $PLATFORM = "solaris" ]
then
	mkdir -p $OUTPUT_DIR/process_info/memory_maps 2> /dev/null
    ps -e -o pid | grep '[0-9]' | while read pid
    do
        pmap -x $pid 1> "$OUTPUT_DIR/process_info/memory_maps/${pid}_pmap.txt" 2>/dev/null
    done
fi

if [ $PLATFORM = "aix" ]
then
	mkdir -p $OUTPUT_DIR/process_info/memory_maps 2> /dev/null
    ps -e -o pid | grep '[0-9]' | while read pid
    do
        svmon -P $pid 1> "$OUTPUT_DIR/process_info/memory_maps/${pid}_svmon.txt" 2>/dev/null
    done
fi

echo "  ${COL_ENTRY}>${RESET} Process network namespaces"
for pid in /proc/[0-9]*; do
    PID_NUM=$(basename $pid)
    if [ -d "$pid/net" ]; then
        cat $pid/net/tcp > $OUTPUT_DIR/process_info/net_tcp_${PID_NUM}.txt 2> /dev/null
        cat $pid/net/udp > $OUTPUT_DIR/process_info/net_udp_${PID_NUM}.txt 2> /dev/null
        cat $pid/net/tcp6 > $OUTPUT_DIR/process_info/net_tcp6_${PID_NUM}.txt 2> /dev/null
        cat $pid/net/udp6 > $OUTPUT_DIR/process_info/net_udp6_${PID_NUM}.txt 2> /dev/null
    fi
done

echo "  ${COL_ENTRY}>${RESET} Process file descriptors"
mkdir $OUTPUT_DIR/process_info/file_descriptors 2>/dev/null

if [ -d "/proc" ]
then
    ls -1 /proc 2>/dev/null | grep '^[0-9]' | grep -v '[^0-9]' | while read pid
    do
        if [ -d "/proc/$pid/fd" ]
        then
            ls -la "/proc/$pid/fd/" 1> "$OUTPUT_DIR/process_info/file_descriptors/${pid}_fd_list.txt" 2>/dev/null
            
            ls "/proc/$pid/fd/" 2>/dev/null | while read fd
            do
                link=`readlink "/proc/$pid/fd/$fd" 2>/dev/null`
                echo "$fd -> $link" 1>> "$OUTPUT_DIR/process_info/file_descriptors/${pid}_fd_resolved.txt" 2>/dev/null
            done
        fi
    done
fi

echo "  ${COL_ENTRY}>${RESET} Hidden process detection"
mkdir $OUTPUT_DIR/process_info/hidden_detection 2>/dev/null


if [ -d "/proc" ]
then
    ls -1 /proc 2>/dev/null | grep '^[0-9][0-9]*$' | sort -n > $OUTPUT_DIR/process_info/hidden_detection/proc_pids.txt 2>/dev/null
 
    if [ $PLATFORM = "linux" -o $PLATFORM = "android" ]
    then
        ps -e -o pid 2>/dev/null | grep -v PID | sed 's/^[ ]*//' | grep '^[0-9][0-9]*$' | sort -n > $OUTPUT_DIR/process_info/hidden_detection/ps_pids.txt 2>/dev/null
    elif [ $PLATFORM = "solaris" ]
    then
        ps -e -o pid 2>/dev/null | grep -v PID | sed 's/^[ ]*//' | grep '^[0-9][0-9]*$' | sort -n > $OUTPUT_DIR/process_info/hidden_detection/ps_pids.txt 2>/dev/null
    elif [ $PLATFORM = "aix" ]
    then
        ps -e -o pid 2>/dev/null | tail -n +2 | sed 's/^[ ]*//' | grep '^[0-9][0-9]*$' | sort -n > $OUTPUT_DIR/process_info/hidden_detection/ps_pids.txt 2>/dev/null
    else
        ps -e 2>/dev/null | awk 'NR>1 {print $1}' | grep '^[0-9][0-9]*$' | sort -n > $OUTPUT_DIR/process_info/hidden_detection/ps_pids.txt 2>/dev/null
    fi

    if [ -f "$OUTPUT_DIR/process_info/hidden_detection/proc_pids.txt" -a -f "$OUTPUT_DIR/process_info/hidden_detection/ps_pids.txt" ]
    then
        # PIDs in /proc but not in ps (potentially hidden)
        comm -13 $OUTPUT_DIR/process_info/hidden_detection/ps_pids.txt $OUTPUT_DIR/process_info/hidden_detection/proc_pids.txt > $OUTPUT_DIR/process_info/hidden_detection/hidden_pids_in_proc.txt 2>/dev/null
        
        # PIDs in ps but not in /proc (shouldn't happen normally)
        comm -23 $OUTPUT_DIR/process_info/hidden_detection/ps_pids.txt $OUTPUT_DIR/process_info/hidden_detection/proc_pids.txt > $OUTPUT_DIR/process_info/hidden_detection/hidden_pids_in_ps.txt 2>/dev/null
    fi
fi

# Check for process hiding techniques
echo "  ${COL_ENTRY}>${RESET} Process hiding technique detection"

# 1. Check for bind mounts over /proc entries
mount 2>/dev/null | grep "/proc/[0-9]" > $OUTPUT_DIR/process_info/hidden_detection/proc_bind_mounts.txt 2>/dev/null

# 2. Check LD_PRELOAD which is commonly used for hiding
if [ -f "/etc/ld.so.preload" ]
then
    echo "=== Content of /etc/ld.so.preload ===" > $OUTPUT_DIR/process_info/hidden_detection/ld_so_preload.txt
    cat /etc/ld.so.preload >> $OUTPUT_DIR/process_info/hidden_detection/ld_so_preload.txt 2>/dev/null
    echo "" >> $OUTPUT_DIR/process_info/hidden_detection/ld_so_preload.txt
    echo "=== File permissions ===" >> $OUTPUT_DIR/process_info/hidden_detection/ld_so_preload.txt
    ls -la /etc/ld.so.preload >> $OUTPUT_DIR/process_info/hidden_detection/ld_so_preload.txt 2>/dev/null
    echo "" >> $OUTPUT_DIR/process_info/hidden_detection/ld_so_preload.txt
    echo "=== File modification time ===" >> $OUTPUT_DIR/process_info/hidden_detection/ld_so_preload.txt
    stat /etc/ld.so.preload >> $OUTPUT_DIR/process_info/hidden_detection/ld_so_preload.txt 2>/dev/null
fi

# 3. Check for LD_PRELOAD in running processes
if [ -d "/proc" ]
then
    echo "=== Processes with LD_PRELOAD set ===" > $OUTPUT_DIR/process_info/hidden_detection/processes_with_ld_preload.txt
    ls -1 /proc 2>/dev/null | grep '^[0-9][0-9]*$' | while read pid
    do
        if [ -r "/proc/$pid/environ" ]
        then
            if grep -a "LD_PRELOAD" "/proc/$pid/environ" >/dev/null 2>&1
            then
                echo "PID $pid:" >> $OUTPUT_DIR/process_info/hidden_detection/processes_with_ld_preload.txt
                tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep "LD_PRELOAD" >> $OUTPUT_DIR/process_info/hidden_detection/processes_with_ld_preload.txt
                if [ -r "/proc/$pid/cmdline" ]
                then
                    echo "Command: `tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null`" >> $OUTPUT_DIR/process_info/hidden_detection/processes_with_ld_preload.txt
                fi
                echo "" >> $OUTPUT_DIR/process_info/hidden_detection/processes_with_ld_preload.txt
            fi
        fi
    done
fi

# 4. Platform-specific hidden process checks
if [ $PLATFORM = "linux" -o $PLATFORM = "android" ]
then
    # Kernel threads (shown in [] brackets)
    ps aux 2>/dev/null | grep '\[.*\]' > $OUTPUT_DIR/process_info/hidden_detection/kernel_threads.txt 2>/dev/null
    
    # Collect all /proc/*/stat for analysis (limit to first 1000 to avoid hanging)
    echo "=== Process stat information ===" > $OUTPUT_DIR/process_info/hidden_detection/all_proc_stat.txt
    ls -1 /proc 2>/dev/null | grep '^[0-9][0-9]*$' | head -1000 | while read pid
    do
        if [ -r "/proc/$pid/stat" ]
        then
            stat_info=`cat "/proc/$pid/stat" 2>/dev/null | head -1`
            if [ -n "$stat_info" ]
            then
                echo "$pid: $stat_info" >> $OUTPUT_DIR/process_info/hidden_detection/all_proc_stat.txt
            fi
        fi
    done
    
    # Check for orphaned network connections (connections without visible process)
    echo "=== Orphaned network connections ===" > $OUTPUT_DIR/process_info/hidden_detection/orphan_connections.txt
    
    # Try netstat first
    if [ -x /bin/netstat -o -x /usr/bin/netstat -o -x /sbin/netstat ]
    then
        netstat -tulpn 2>/dev/null | grep -v "PID/Program" | awk '$NF == "-" {print}' >> $OUTPUT_DIR/process_info/hidden_detection/orphan_connections.txt 2>/dev/null
    fi
    
    # Also try ss if available
    if [ -x /bin/ss -o -x /usr/bin/ss -o -x /sbin/ss ]
    then
        echo "" >> $OUTPUT_DIR/process_info/hidden_detection/orphan_connections.txt
        echo "=== From ss command ===" >> $OUTPUT_DIR/process_info/hidden_detection/orphan_connections.txt
        ss -tulpn 2>/dev/null | grep -v "users:" | grep -v "PID/Program" >> $OUTPUT_DIR/process_info/hidden_detection/orphan_connections.txt 2>/dev/null
    fi
    
    # Check /proc/net for connections and correlate with processes
    echo "=== Network connections from /proc/net ===" > $OUTPUT_DIR/process_info/hidden_detection/proc_net_connections.txt
    for proto in tcp tcp6 udp udp6
    do
        if [ -r "/proc/net/$proto" ]
        then
            echo "[$proto]" >> $OUTPUT_DIR/process_info/hidden_detection/proc_net_connections.txt
            cat "/proc/net/$proto" >> $OUTPUT_DIR/process_info/hidden_detection/proc_net_connections.txt 2>/dev/null
            echo "" >> $OUTPUT_DIR/process_info/hidden_detection/proc_net_connections.txt
        fi
    done
fi

# 5. Check for process name anomalies
if [ -d "/proc" ]
then
    echo "=== Process name anomalies ===" > $OUTPUT_DIR/process_info/hidden_detection/process_name_anomalies.txt
    
    # Look for processes with suspicious names
    ls -1 /proc 2>/dev/null | grep '^[0-9][0-9]*$' | while read pid
    do
        if [ -r "/proc/$pid/comm" -a -r "/proc/$pid/cmdline" ]
        then
            comm_name=`cat "/proc/$pid/comm" 2>/dev/null | head -1`
            cmdline=`tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -1`
            
            # Check for empty or suspicious names
            if [ -z "$comm_name" -o "$comm_name" = "." -o "$comm_name" = ".." ]
            then
                echo "PID $pid has suspicious comm name: '$comm_name'" >> $OUTPUT_DIR/process_info/hidden_detection/process_name_anomalies.txt
                echo "  cmdline: $cmdline" >> $OUTPUT_DIR/process_info/hidden_detection/process_name_anomalies.txt
            fi
            
            # Check for very short process names (often used by rootkits)
            if [ ${#comm_name} -le 2 ] 2>/dev/null
            then
                echo "PID $pid has very short name: '$comm_name'" >> $OUTPUT_DIR/process_info/hidden_detection/process_name_anomalies.txt
                echo "  cmdline: $cmdline" >> $OUTPUT_DIR/process_info/hidden_detection/process_name_anomalies.txt
            fi
        fi
    done
fi

# 6. Check for GID process hiding trick
if [ $PLATFORM = "linux" ]
then
    echo "=== Checking for GID hiding trick ===" > $OUTPUT_DIR/process_info/hidden_detection/gid_hiding_check.txt
    
    # Some rootkits hide processes by setting GID to a special value
    # Check /proc/*/stat for processes with GID 0x80000000 or similar
    ls -1 /proc 2>/dev/null | grep '^[0-9][0-9]*$' | while read pid
    do
        if [ -r "/proc/$pid/status" ]
        then
            gid_line=`grep "^Gid:" "/proc/$pid/status" 2>/dev/null`
            if echo "$gid_line" | grep -E "(2147483647|4294967295|80000000)" >/dev/null 2>&1
            then
                echo "PID $pid has suspicious GID: $gid_line" >> $OUTPUT_DIR/process_info/hidden_detection/gid_hiding_check.txt
                if [ -r "/proc/$pid/cmdline" ]
                then
                    echo "  Command: `tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null`" >> $OUTPUT_DIR/process_info/hidden_detection/gid_hiding_check.txt
                fi
            fi
        fi
    done
fi

# 7. Summary report
echo "  ${COL_ENTRY}>${RESET} Creating hidden process summary"
echo "=== Hidden Process Detection Summary ===" > $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt
echo "Report generated on: `date`" >> $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt
echo "" >> $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt

# Count hidden PIDs
if [ -f "$OUTPUT_DIR/process_info/hidden_detection/hidden_pids_in_proc.txt" ]
then
    hidden_count=`wc -l < $OUTPUT_DIR/process_info/hidden_detection/hidden_pids_in_proc.txt 2>/dev/null`
    echo "Hidden PIDs found in /proc but not ps: $hidden_count" >> $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt
    if [ "$hidden_count" -gt 0 ]
    then
        echo "PIDs: `cat $OUTPUT_DIR/process_info/hidden_detection/hidden_pids_in_proc.txt | tr '\n' ' '`" >> $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt
    fi
fi

# Check for LD_PRELOAD
if [ -f "/etc/ld.so.preload" ]
then
    echo "" >> $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt
    echo "WARNING: /etc/ld.so.preload exists (commonly used for hiding)" >> $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt
fi

# Check for bind mounts
if [ -s "$OUTPUT_DIR/process_info/hidden_detection/proc_bind_mounts.txt" ]
then
    echo "" >> $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt
    echo "WARNING: Bind mounts found over /proc entries" >> $OUTPUT_DIR/process_info/hidden_detection/SUMMARY.txt
fi

# Extract key process information for analysis
echo "  ${COL_ENTRY}>${RESET} Process analysis summaries"
# Find processes with deleted executables
grep -l "(deleted)" $OUTPUT_DIR/process_info/fd_detailed_*.txt 2> /dev/null | sed 's/.*fd_detailed_//' | sed 's/.txt$//' > $OUTPUT_DIR/process_info/pids_with_deleted_files.txt 2> /dev/null

# Find processes running from temporary locations
grep -E "(/tmp/|/var/tmp/|/dev/shm/)" $OUTPUT_DIR/process_info/cmdline/cmdline_*.txt 2> /dev/null | cut -d: -f1 | sed 's/.*cmdline_//' | sed 's/.txt$//' | sort -u > $OUTPUT_DIR/process_info/pids_from_tmp_locations.txt 2> /dev/null

# Extract unique loaded libraries
cat $OUTPUT_DIR/process_info/maps/maps_*.txt 2> /dev/null | grep -E "\.(so|dylib|dll)" | awk '{print $6}' | sort -u > $OUTPUT_DIR/process_info/all_loaded_libraries.txt 2> /dev/null

# Find suspicious library injections
grep -l -E "(/tmp/|/var/tmp/|/dev/shm/)" $OUTPUT_DIR/process_info/maps/maps_*.txt 2> /dev/null | sed 's/.*maps_//' | sed 's/.txt$//' > $OUTPUT_DIR/process_info/pids_with_tmp_libraries.txt 2> /dev/null

# Platform-specific process hashing (existing code, no changes)
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
	
	# Collect capability information
	for pid in /proc/[0-9]*; do
	    PID_NUM=$(basename $pid)
	    grep -E "^Cap" $pid/status > $OUTPUT_DIR/process_info/status/capabilities_${PID_NUM}.txt 2> /dev/null
	done
	
	# Collect NUMA information
	for pid in /proc/[0-9]*; do
	    PID_NUM=$(basename $pid)
	    cat $pid/numa_maps > $OUTPUT_DIR/process_info/maps/numa_maps_${PID_NUM}.txt 2> /dev/null
	done
fi

if [ $PLATFORM = "aix" ]
then
	find /proc/[0-9]*/object/a.out -type l -exec sha256sum {} \; >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	find /proc/[0-9]*/object/a.out -type l -exec sha1sum {} \; >> $OUTPUT_DIR/process_info/sha1sum_running_processes 2> /dev/null
	find /proc/[0-9]*/object/a.out -type l -exec md5sum {} \; >> $OUTPUT_DIR/process_info/md5sum_running_processes 2> /dev/null
	find /proc/[0-9]*/object/a.out -type l -exec openssl dgst -sha256 {} \; >> $OUTPUT_DIR/process_info/openssl_sha256_running_processes 2> /dev/null
	
	for pid in /proc/[0-9]*; do
	    PID_NUM=$(basename $pid)
	    # AIX specific proc files
	    cat $pid/psinfo > $OUTPUT_DIR/process_info/psinfo_${PID_NUM}.dat 2> /dev/null
	    cat $pid/map > $OUTPUT_DIR/process_info/maps/aix_map_${PID_NUM}.txt 2> /dev/null
	    cat $pid/sigact > $OUTPUT_DIR/process_info/sigact_${PID_NUM}.txt 2> /dev/null
	done
fi

if [ $PLATFORM = "solaris" ]
then
	find /proc/[0-9]*/path/a.out -type l -exec sha256sum {} \; >> $OUTPUT_DIR/process_info/sha256sum_running_processes 2> /dev/null
	find /proc/[0-9]*/path/a.out -type l -exec sha1sum {} \; >> $OUTPUT_DIR/process_info/sha1sum_running_processes 2> /dev/null
	find /proc/[0-9]*/path/a.out -type l -exec md5sum {} \; >> $OUTPUT_DIR/process_info/md5sum_running_processes 2> /dev/null
	find /proc/[0-9]*/path/a.out -type l -exec openssl dgst -sha256 {} \; >> $OUTPUT_DIR/process_info/openssl_sha256_running_processes 2> /dev/null
	
	for pid in /proc/[0-9]*; do
	    PID_NUM=$(basename $pid)
	    # Solaris binary psinfo
	    strings $pid/psinfo > $OUTPUT_DIR/process_info/psinfo_strings_${PID_NUM}.txt 2> /dev/null
	    # Process credentials
	    cat $pid/cred > $OUTPUT_DIR/process_info/cred_${PID_NUM}.dat 2> /dev/null
	    # LWP (lightweight process) info
	    ls -la $pid/lwp > $OUTPUT_DIR/process_info/lwp_${PID_NUM}.txt 2> /dev/null
	done
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
	
	# Since macOS doesn't have /proc, collect what we can
	ps -A -o pid,ppid,user,nice,pri,vsz,rss,stat,start,time,command > $OUTPUT_DIR/process_info/ps_detailed_mac.txt 2> /dev/null
	# Use lsof for process file handles
	lsof -n -P > $OUTPUT_DIR/process_info/lsof_all_mac.txt 2> /dev/null
fi

# Platform-specific process tree tools (existing code, no changes)
if [ $PLATFORM = "solaris" ]
then
	ptree 1> $OUTPUT_DIR/general/ptree.txt 2> /dev/null
	# pfiles for detailed file info
	ps -e -o pid | grep -v PID | while read pid; do
	    pfiles $pid > $OUTPUT_DIR/process_info/pfiles_$pid.txt 2> /dev/null
	done
	# pmap for memory mappings
	ps -e -o pid | grep -v PID | while read pid; do
	    pmap -x $pid > $OUTPUT_DIR/process_info/pmap_$pid.txt 2> /dev/null
	done
fi

if [ $PLATFORM = "aix" ]
then
	proctree -a 1> $OUTPUT_DIR/general/proctree_a.txt 2> /dev/null
	pstat -a 1> $OUTPUT_DIR/general/pstat_a.txt 2> /dev/null
	pstat -f 1> $OUTPUT_DIR/general/pstat_f.txt 2> /dev/null
	pstat -A 1> $OUTPUT_DIR/general/pstat_A.txt 2> /dev/null
	pstat -p 1> $OUTPUT_DIR/general/pstat_p.txt 2> /dev/null
	# procfiles for file info
	ps -e -o pid | grep -v PID | while read pid; do
	    procfiles $pid > $OUTPUT_DIR/process_info/procfiles_$pid.txt 2> /dev/null
	done
	# svmon for memory
	svmon -P ALL > $OUTPUT_DIR/process_info/svmon_all.txt 2> /dev/null
fi

if [ $PLATFORM = "android" ]
then
	ps -A 1> $OUTPUT_DIR/general/android_ps-all 2> /dev/null
	ps -A -f -l 1> $OUTPUT_DIR/general/android_ps-all-F-l 2> /dev/null
fi

# Create process analysis summary
echo "  ${COL_ENTRY}>${RESET} Creating process analysis summary"
echo "Process Analysis Summary" > $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
echo "========================" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
echo "Platform: $PLATFORM" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
echo "Collection Date: $(date)" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
echo "" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt

# Count various findings
TOTAL_PROCS=$(ls -1 $OUTPUT_DIR/process_info/cmdline/cmdline_*.txt 2> /dev/null | wc -l)
echo "Total processes analyzed: $TOTAL_PROCS" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
if [ -f "$OUTPUT_DIR/process_info/deleted_processes_ids.txt" ]; then
    DELETED_COUNT=$(wc -l < $OUTPUT_DIR/process_info/deleted_processes_ids.txt)
    echo "Processes with deleted executables: $DELETED_COUNT" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
fi
if [ -f "$OUTPUT_DIR/process_info/pids_from_tmp_locations.txt" ]; then
    TMP_COUNT=$(wc -l < $OUTPUT_DIR/process_info/pids_from_tmp_locations.txt)
    echo "Processes running from /tmp locations: $TMP_COUNT" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
fi
if [ -f "$OUTPUT_DIR/process_info/hidden_pids_in_proc.txt" ]; then
    HIDDEN_COUNT=$(wc -l < $OUTPUT_DIR/process_info/hidden_pids_in_proc.txt)
    echo "Potentially hidden PIDs (in /proc but not ps): $HIDDEN_COUNT" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
fi
if [ -f "$OUTPUT_DIR/process_info/proc_bind_mounts.txt" ]; then
    BIND_COUNT=$(wc -l < $OUTPUT_DIR/process_info/proc_bind_mounts.txt)
    echo "Bind mounts in /proc: $BIND_COUNT" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
fi
echo "" >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt
echo "Check individual files for detailed information." >> $OUTPUT_DIR/process_info/ANALYSIS_SUMMARY.txt

echo "  ${COL_ENTRY}>${RESET} Cron and other scheduler files"
mkdir $OUTPUT_DIR/general/crontabs/ 2> /dev/null

# System-wide crontab
if [ -f "/etc/crontab" ] && [ -r "/etc/crontab" ]; then
	cp /etc/crontab $OUTPUT_DIR/general/crontabs/etc-crontab.txt 2> /dev/null
	ls -la /etc/crontab > $OUTPUT_DIR/general/crontabs/etc-crontab-perms.txt 2> /dev/null
fi

# Current user's crontab - handle different platforms
if [ $PLATFORM = "aix" ]
then
    crontab -v 1> $OUTPUT_DIR/general/crontab.txt 2> /dev/null
else
    crontab -l 1> $OUTPUT_DIR/general/crontab.txt 2> /dev/null
fi

# Also save in crontabs directory for consistency
crontab -l > $OUTPUT_DIR/general/crontabs/current_user_crontab.txt 2> /dev/null

# Collect cron spool directories - consolidated
if [ -d /var/cron/ ]
then
	cp -R /var/cron/ $OUTPUT_DIR/general/crontabs/var_cron 2> /dev/null
fi

if [ -d /var/adm/cron/ ]
then
	cp -R /var/adm/cron/ $OUTPUT_DIR/general/crontabs/var_adm_cron 2> /dev/null
fi

if [ -d /var/spool/cron/ ]
then
	cp -R /var/spool/cron/ $OUTPUT_DIR/general/crontabs/var_spool_cron 2> /dev/null
fi

# User crontabs with proper enumeration - avoiding duplication
if [ -d /var/spool/cron/crontabs ]
then
    mkdir $OUTPUT_DIR/general/crontabs 2> /dev/null
    ls -la /var/spool/cron/crontabs/ 2> /dev/null > $OUTPUT_DIR/general/crontabs/user_crontabs_perms.txt 2> /dev/null
    
    for name in `ls /var/spool/cron/crontabs/`
    do
        if [ -f /var/spool/cron/crontabs/$name ]
        then
            ls -lL /var/spool/cron/crontabs/$name 1>> $OUTPUT_DIR/general/crontabs/perms 2> /dev/null
            cp /var/spool/cron/crontabs/$name $OUTPUT_DIR/general/crontabs/$name 2> /dev/null
            
            # Also add to consolidated view
            echo "=== Crontab for user: $name ===" >> $OUTPUT_DIR/general/crontabs/all_user_crontabs.txt
            cat /var/spool/cron/crontabs/$name >> $OUTPUT_DIR/general/crontabs/all_user_crontabs.txt 2> /dev/null
            echo "" >> $OUTPUT_DIR/general/crontabs/all_user_crontabs.txt
            
            # Check permissions on referenced files
            cat /var/spool/cron/crontabs/$name 2> /dev/null | grep -v "^#" | while read null null null null null cmd null
            do
                ls -lL $cmd 1>> $OUTPUT_DIR/general/crontabs/perms 2> /dev/null
            done
        fi
    done
fi

# Alternative location for user crontabs
if [ -d /var/spool/cron/tabs ] && [ ! -d /var/spool/cron/crontabs ]
then
    ls -la /var/spool/cron/tabs/ > $OUTPUT_DIR/general/crontabs/user_tabs_perms.txt 2> /dev/null
    
    for name in `ls /var/spool/cron/tabs/`
    do
        if [ -f /var/spool/cron/tabs/$name ]
        then
            cp /var/spool/cron/tabs/$name $OUTPUT_DIR/general/crontabs/$name 2> /dev/null
            
            echo "=== Crontab for user: $name ===" >> $OUTPUT_DIR/general/crontabs/all_user_crontabs_alt.txt
            cat /var/spool/cron/tabs/$name >> $OUTPUT_DIR/general/crontabs/all_user_crontabs_alt.txt 2> /dev/null
            echo "" >> $OUTPUT_DIR/general/crontabs/all_user_crontabs_alt.txt
        fi
    done
fi

# Collect cron.d and periodic directories with permissions
if [ -d /etc/cron.d ]
then
    mkdir $OUTPUT_DIR/general/cron.d 2> /dev/null
    ls -la /etc/cron.d/ > $OUTPUT_DIR/general/cron.d/directory_perms.txt 2> /dev/null
    
    for name in `ls /etc/cron.d/`
    do
        if [ -f /etc/cron.d/$name ]
        then
            ls -lL /etc/cron.d/$name 1>> $OUTPUT_DIR/general/cron.d/perms 2> /dev/null
            cp /etc/cron.d/$name $OUTPUT_DIR/general/cron.d/$name 2> /dev/null
            
            # Linux-specific: check user permissions
            if [ $PLATFORM = "linux" ]
            then
                cat /etc/cron.d/$name 2> /dev/null | grep -v "^#" | while read null null null null null user cmd null
                do
                    echo "$user:" 1>> $OUTPUT_DIR/general/cron.d/perms 2> /dev/null
                    ls -lL $cmd 1>> $OUTPUT_DIR/general/cron.d/perms 2> /dev/null
                done
            fi
        fi
    done
fi

# Periodic cron directories
for period in hourly daily weekly monthly
do
    if [ -d /etc/cron.$period ]
    then
        mkdir $OUTPUT_DIR/general/cron.$period 2> /dev/null
        ls -la /etc/cron.$period/ > $OUTPUT_DIR/general/cron.$period/directory_perms.txt 2> /dev/null
        
        for name in `ls /etc/cron.$period/`
        do
            if [ -f /etc/cron.$period/$name ]
            then
                ls -lL /etc/cron.$period/$name 1>> $OUTPUT_DIR/general/cron.$period/perms 2> /dev/null
                cp /etc/cron.$period/$name $OUTPUT_DIR/general/cron.$period/$name 2> /dev/null
            fi
        done
    fi
done

# Access control files
for file in cron.allow cron.deny at.allow at.deny
do
    if [ -f /etc/$file ]
    then
        cp /etc/$file $OUTPUT_DIR/general/crontabs/$file 2> /dev/null
        ls -la /etc/$file >> $OUTPUT_DIR/general/crontabs/${file}_perms.txt 2> /dev/null
    fi
done

# Anacron
if [ -f /etc/anacrontab ]
then
    cp /etc/anacrontab $OUTPUT_DIR/general/crontabs/anacrontab 2> /dev/null
fi

if [ -d /var/spool/anacron/ ]
then
    cp -R /var/spool/anacron/ $OUTPUT_DIR/general/crontabs/var_spool_anacron 2> /dev/null
fi

# At scheduler
echo "  ${COL_ENTRY}>${RESET} At scheduler"
if [ -d /var/spool/at/ ]
then
    cp -R /var/spool/at/ $OUTPUT_DIR/general/crontabs/var_spool_at 2> /dev/null
    ls -la /var/spool/at/ > $OUTPUT_DIR/general/crontabs/at_spool_listing.txt 2> /dev/null
fi

atq > $OUTPUT_DIR/general/crontabs/atq_list.txt 2> /dev/null

# Detailed at jobs if running as root
if [ $(id -u 2> /dev/null) -eq 0 ] 2> /dev/null || [ "$USER" = "root" ]
then
    for job in $(atq 2> /dev/null | awk '{print $1}')
    do
        echo "=== At job $job ===" >> $OUTPUT_DIR/general/crontabs/at_jobs_details.txt
        at -c $job >> $OUTPUT_DIR/general/crontabs/at_jobs_details.txt 2> /dev/null
        echo "" >> $OUTPUT_DIR/general/crontabs/at_jobs_details.txt
    done
fi

# Systemd timers and services
echo "  ${COL_ENTRY}>${RESET} Systemd timers and services"
mkdir -p $OUTPUT_DIR/general/systemd 2> /dev/null

if [ -x /bin/systemctl ] || [ -x /usr/bin/systemctl ]
then
    systemctl list-timers --all --no-pager > $OUTPUT_DIR/general/systemd/timers_all.txt 2> /dev/null
    systemctl list-units --all --no-pager > $OUTPUT_DIR/general/systemd/units_all.txt 2> /dev/null
    systemctl list-units --failed --no-pager > $OUTPUT_DIR/general/systemd/units_failed.txt 2> /dev/null
    systemctl list-unit-files --type=service --no-pager > $OUTPUT_DIR/general/systemd/services_all.txt 2> /dev/null
    systemctl list-unit-files --type=timer --no-pager > $OUTPUT_DIR/general/systemd/timer_units.txt 2> /dev/null
fi

# Collect systemd timer files
mkdir -p $OUTPUT_DIR/general/systemd/timers 2> /dev/null
for dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system
do
    if [ -d $dir ]
    then
        find $dir -name "*.timer" -type f -exec cp {} $OUTPUT_DIR/general/systemd/timers/ \; 2> /dev/null
        # Also copy the whole directory for complete context
        if [ $dir = "/etc/systemd/system" ]
        then
            cp -R $dir $OUTPUT_DIR/general/systemd/etc_systemd_system 2> /dev/null
        fi
    fi
done

# Platform-specific schedulers
echo "  ${COL_ENTRY}>${RESET} Platform-specific schedulers"

# macOS
if [ $PLATFORM = "mac" ]
then
    # Additional crontab locations
    crontab -v 1> $OUTPUT_DIR/general/crontab-v.txt 2> /dev/null
    
    # Various cron locations
    for dir in /var/at /private/var/at/tabs /usr/lib/cron/jobs /usr/lib/cron/tabs
    do
        if [ -d $dir ]
        then
            cp -R $dir $OUTPUT_DIR/general/crontabs/$(echo $dir | tr '/' '_') 2> /dev/null
        fi
    done
    
    # Periodic configurations
    for file in /etc/periodic.conf /etc/periodic.conf.local
    do
        if [ -f $file ]
        then
            cp $file $OUTPUT_DIR/general/crontabs/ 2> /dev/null
        fi
    done
    
    # Periodic directories
    if [ -d /etc/periodic ]
    then
        cp -R /etc/periodic/ $OUTPUT_DIR/general/crontabs/etc_periodic 2> /dev/null
    fi
    
    for period in daily weekly monthly
    do
        if [ -d /etc/$period.local ]
        then
            cp -R /etc/$period.local/ $OUTPUT_DIR/general/crontabs/${period}_local 2> /dev/null
        fi
        if [ -d /etc/periodic/$period ]
        then
            cp -R /etc/periodic/$period/ $OUTPUT_DIR/general/crontabs/periodic_$period 2> /dev/null
        fi
    done
    
    if [ -d /usr/local/etc/periodic ]
    then
        cp -R /usr/local/etc/periodic/ $OUTPUT_DIR/general/crontabs/usr_local_etc_periodic 2> /dev/null
    fi
    
    # LaunchAgents and LaunchDaemons
    for type in LaunchAgents LaunchDaemons StartupItems
    do
        for prefix in "" "/System"
        do
            if [ -d ${prefix}/Library/$type ]
            then
                cp -R ${prefix}/Library/$type/ $OUTPUT_DIR/general/crontabs/$(echo ${prefix}_Library_$type | sed 's/^_//') 2> /dev/null
            fi
        done
    done
    
    # User LaunchAgents
    for user_home in /Users/*
    do
        if [ -d "$user_home/Library/LaunchAgents/" ]
        then
            USERNAME=$(basename $user_home)
            mkdir -p $OUTPUT_DIR/general/crontabs/User_LaunchAgents_$USERNAME 2> /dev/null
            cp -R $user_home/Library/LaunchAgents/ $OUTPUT_DIR/general/crontabs/User_LaunchAgents_$USERNAME/ 2> /dev/null
        fi
    done
    
    # List loaded launch items
    launchctl list > $OUTPUT_DIR/general/crontabs/launchctl_list.txt 2> /dev/null
fi

# Android
if [ $PLATFORM = "android" ]
then
    crontab -l 1> $OUTPUT_DIR/general/android_crontab-l 2> /dev/null
    if [ -d /data/crontab/ ]
    then
        cp -R /data/crontab/ $OUTPUT_DIR/general/crontabs/data_crontab 2> /dev/null
    fi
fi

# Solaris
if [ $PLATFORM = "solaris" ]
then
    # SMF scheduled services
    svcs -a > $OUTPUT_DIR/general/crontabs/smf_services_all.txt 2> /dev/null
    svcs -a | grep -E "(online|offline)" > $OUTPUT_DIR/general/crontabs/smf_services_active.txt 2> /dev/null
    # Legacy rc scripts
    if [ -d /etc/rc2.d/ ]
    then
        ls -la /etc/rc*.d/ > $OUTPUT_DIR/general/crontabs/rc_scripts.txt 2> /dev/null
    fi
fi

# AIX
if [ $PLATFORM = "aix" ]
then
    # ODM cron entries
    odmget cron > $OUTPUT_DIR/general/crontabs/aix_odm_cron.txt 2> /dev/null
    # List subsystems
    lssrc -a > $OUTPUT_DIR/general/crontabs/aix_subsystems.txt 2> /dev/null
fi

# Analyze collected cron files for suspicious patterns
echo "  ${COL_ENTRY}>${RESET} Analyzing cron entries"

find $OUTPUT_DIR/general/crontabs/ -type f 2> /dev/null | while read cronfile
do
    # Skip binary files
    if file "$cronfile" 2> /dev/null | grep -q "text"
    then
        # Look for suspicious patterns
        grep -H -E "(wget|curl|nc|netcat|/tmp/|/dev/shm/|base64|bash -i|sh -i|exec|eval)" "$cronfile" >> $OUTPUT_DIR/general/crontabs/suspicious_cron_entries.txt 2> /dev/null
        
        # Look for hidden files being executed
        grep -H -E "/\.[^/][^/]*" "$cronfile" | grep -v "^#" >> $OUTPUT_DIR/general/crontabs/hidden_file_cron_entries.txt 2> /dev/null
        
        # Look for cron entries running as root
        grep -H -E "^[^#]*root" "$cronfile" >> $OUTPUT_DIR/general/crontabs/root_cron_entries.txt 2> /dev/null
        
        # Look for unusual paths
        grep -H -E "(/var/tmp/|/usr/tmp/|/home/[^/]+/\.|/opt/\.|/usr/local/\.)" "$cronfile" >> $OUTPUT_DIR/general/crontabs/unusual_path_entries.txt 2> /dev/null
    fi
done

# Also check systemd timers for suspicious content
if [ -d $OUTPUT_DIR/general/systemd/timers ]
then
    find $OUTPUT_DIR/general/systemd/timers -name "*.timer" -type f 2> /dev/null | while read timer
    do
        grep -H -E "(ExecStart=.*(/tmp/|/dev/shm/|wget|curl|nc|bash -i))" "$timer" >> $OUTPUT_DIR/general/systemd/suspicious_timers.txt 2> /dev/null
    done
fi

# Create analysis summary
echo "Cron and Scheduler Analysis Summary" > $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
echo "===================================" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
echo "Collection Date: $(date)" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
echo "Platform: $PLATFORM" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
echo "" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt

# Count findings
if [ -f "$OUTPUT_DIR/general/crontabs/all_user_crontabs.txt" ] || [ -f "$OUTPUT_DIR/general/crontabs/all_user_crontabs_alt.txt" ]
then
    USER_COUNT=$(grep -c "=== Crontab for user:" $OUTPUT_DIR/general/crontabs/all_user_crontabs*.txt 2> /dev/null | awk -F: '{sum+=$2} END {print sum}')
    echo "User crontabs found: ${USER_COUNT:-0}" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
fi

for check in suspicious_cron_entries hidden_file_cron_entries root_cron_entries unusual_path_entries
do
    if [ -f "$OUTPUT_DIR/general/crontabs/${check}.txt" ]
    then
        COUNT=$(wc -l < $OUTPUT_DIR/general/crontabs/${check}.txt 2> /dev/null || echo 0)
        echo "$(echo $check | tr '_' ' '): $COUNT" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
    fi
done

if [ -f "$OUTPUT_DIR/general/systemd/timers_all.txt" ]
then
    TIMER_COUNT=$(grep -c "\.timer" $OUTPUT_DIR/general/systemd/timers_all.txt 2> /dev/null || echo 0)
    echo "Systemd timers: $TIMER_COUNT" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
fi

if [ -f "$OUTPUT_DIR/general/crontabs/launchctl_list.txt" ]
then
    LAUNCH_COUNT=$(wc -l < $OUTPUT_DIR/general/crontabs/launchctl_list.txt 2> /dev/null || echo 0)
    echo "macOS Launch items: $LAUNCH_COUNT" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
fi

echo "" >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt
echo "Check individual files for detailed information." >> $OUTPUT_DIR/general/crontabs/CRON_SUMMARY.txt

# Shared memory directories - moved to end as requested
echo "  ${COL_ENTRY}>${RESET} Shared memory directories"
mkdir $OUTPUT_DIR/general/shared_memory/ 2> /dev/null

# Different platforms use different shared memory locations
SHMEM_DIRS="/dev/shm /run/shm /var/shm /tmp/.ram"

for shm_dir in $SHMEM_DIRS
do
    if [ -d "$shm_dir" ]
    then
        DIR_NAME=$(echo $shm_dir | tr '/' '_' | sed 's/^_//')
        # List contents
        ls -la $shm_dir/ > $OUTPUT_DIR/general/shared_memory/${DIR_NAME}_listing.txt 2> /dev/null
        # Copy small files only to avoid filling disk
        find $shm_dir -type f -size -10M 2> /dev/null | while read file
        do
            FILENAME=$(basename "$file")
            cp "$file" $OUTPUT_DIR/general/shared_memory/${DIR_NAME}_${FILENAME} 2> /dev/null
        done
        
        # Note large files
        find $shm_dir -type f -size +10M -ls >> $OUTPUT_DIR/general/shared_memory/large_files.txt 2> /dev/null
    fi
done

# Platform-specific shared memory locations
if [ $PLATFORM = "solaris" ]
then
    # Solaris uses /tmp for shared memory segments
    if [ -d /tmp/.SHMD ]
    then
        ls -la /tmp/.SHMD/ > $OUTPUT_DIR/general/shared_memory/solaris_shmd_listing.txt 2> /dev/null
    fi
fi

if [ $PLATFORM = "aix" ]
then
    # AIX shared memory info
    ipcs -m > $OUTPUT_DIR/general/shared_memory/aix_ipcs_memory.txt 2> /dev/null
fi

# Find executables
find /dev/shm /run/shm /var/shm /tmp/.ram 2> /dev/null -type f -executable | while read file
do
    echo "$file" >> $OUTPUT_DIR/general/shared_memory/executable_files.txt
    ls -la "$file" >> $OUTPUT_DIR/general/shared_memory/executable_files_details.txt 2> /dev/null
    file "$file" >> $OUTPUT_DIR/general/shared_memory/executable_files_types.txt 2> /dev/null
    
    # Try to identify what process is using it
    lsof "$file" >> $OUTPUT_DIR/general/shared_memory/executable_files_lsof.txt 2> /dev/null
done

# Look for suspicious patterns in filenames
find /dev/shm /run/shm /var/shm /tmp/.ram 2> /dev/null -type f \( -name ".*" -o -name "* *" -o -name "*sh" -o -name "*.elf" \) -ls >> $OUTPUT_DIR/general/shared_memory/suspicious_filenames.txt 2> /dev/null

# Check for common malware patterns
find /dev/shm /run/shm /var/shm /tmp/.ram 2> /dev/null -type f -size -1M | while read file
do
    # Check if it's a script
    if file "$file" 2> /dev/null | grep -qE "(shell script|text)"
    then
        # Look for suspicious content
        if grep -qE "(wget|curl|nc|/bin/sh|/bin/bash|python -c|perl -e|base64)" "$file" 2> /dev/null
        then
            echo "=== Suspicious file: $file ===" >> $OUTPUT_DIR/general/shared_memory/suspicious_scripts.txt
            ls -la "$file" >> $OUTPUT_DIR/general/shared_memory/suspicious_scripts.txt 2> /dev/null
            head -50 "$file" >> $OUTPUT_DIR/general/shared_memory/suspicious_scripts.txt 2> /dev/null
            echo "" >> $OUTPUT_DIR/general/shared_memory/suspicious_scripts.txt
        fi
    fi
done

# Shared memory summary
echo "Shared Memory Analysis Summary" > $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt
echo "==============================" >> $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt
echo "Collection Date: $(date)" >> $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt
echo "" >> $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt
for shm_dir in $SHMEM_DIRS
do
    if [ -d "$shm_dir" ]
    then
        FILE_COUNT=$(find $shm_dir -type f 2> /dev/null | wc -l)
        echo "$shm_dir: $FILE_COUNT files" >> $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt
    fi
done
if [ -f "$OUTPUT_DIR/general/shared_memory/executable_files.txt" ]
then
    EXEC_COUNT=$(wc -l < $OUTPUT_DIR/general/shared_memory/executable_files.txt 2> /dev/null || echo 0)
    echo "Executable files found: $EXEC_COUNT" >> $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt
fi
if [ -f "$OUTPUT_DIR/general/shared_memory/suspicious_scripts.txt" ]
then
    SUSP_COUNT=$(grep -c "=== Suspicious file:" $OUTPUT_DIR/general/shared_memory/suspicious_scripts.txt 2> /dev/null || echo 0)
    echo "Suspicious scripts found: $SUSP_COUNT" >> $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt
fi
echo "" >> $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt
echo "Check individual files for detailed information." >> $OUTPUT_DIR/general/shared_memory/SHMEM_SUMMARY.txt


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

echo "  ${COL_ENTRY}>${RESET} User Activity and Authentication Logs"
mkdir $OUTPUT_DIR/user_activity 2> /dev/null
if [ $PLATFORM = "linux" -o $PLATFORM = "generic" ]
then
    if [ -f /var/log/wtmp ]; then
        cp /var/log/wtmp $OUTPUT_DIR/user_activity/wtmp.raw 2> /dev/null
        last -f /var/log/wtmp 1> $OUTPUT_DIR/user_activity/last-wtmp.txt 2> /dev/null
        last -f /var/log/wtmp -x 1> $OUTPUT_DIR/user_activity/last-wtmp-extended.txt 2> /dev/null
        last -f /var/log/wtmp -i 1> $OUTPUT_DIR/user_activity/last-wtmp-with-ip.txt 2> /dev/null
        last -f /var/log/wtmp -F 1> $OUTPUT_DIR/user_activity/last-wtmp-fulltime.txt 2> /dev/null
        echo "=== Login Statistics ===" > $OUTPUT_DIR/user_activity/login_stats.txt
        echo "Total logins by user:" >> $OUTPUT_DIR/user_activity/login_stats.txt
        last -f /var/log/wtmp 2> /dev/null | awk '{print $1}' | grep -v "^$\|^wtmp\|^reboot" | sort | uniq -c | sort -rn >> $OUTPUT_DIR/user_activity/login_stats.txt
        echo "" >> $OUTPUT_DIR/user_activity/login_stats.txt
        echo "Logins by IP:" >> $OUTPUT_DIR/user_activity/login_stats.txt
        last -f /var/log/wtmp -i 2> /dev/null | awk '{print $3}' | grep -E "^[0-9]" | sort | uniq -c | sort -rn | head -50 >> $OUTPUT_DIR/user_activity/login_stats.txt
    fi
    if [ -f /var/log/btmp ]; then
        cp /var/log/btmp $OUTPUT_DIR/user_activity/btmp.raw 2> /dev/null
        lastb -f /var/log/btmp 1> $OUTPUT_DIR/user_activity/lastb-failed-logins.txt 2> /dev/null
        last -f /var/log/btmp 1> $OUTPUT_DIR/user_activity/last-btmp.txt 2> /dev/null
        echo "=== Failed Login Statistics ===" > $OUTPUT_DIR/user_activity/failed_login_stats.txt
        echo "Failed attempts by user:" >> $OUTPUT_DIR/user_activity/failed_login_stats.txt
        lastb -f /var/log/btmp 2> /dev/null | awk '{print $1}' | grep -v "^$\|^btmp" | sort | uniq -c | sort -rn | head -50 >> $OUTPUT_DIR/user_activity/failed_login_stats.txt
        echo "" >> $OUTPUT_DIR/user_activity/failed_login_stats.txt
        echo "Failed attempts by IP:" >> $OUTPUT_DIR/user_activity/failed_login_stats.txt
        lastb -f /var/log/btmp 2> /dev/null | awk '{print $3}' | grep -E "^[0-9]" | sort | uniq -c | sort -rn | head -50 >> $OUTPUT_DIR/user_activity/failed_login_stats.txt
    fi
    if [ -f /var/run/utmp ]; then
        cp /var/run/utmp $OUTPUT_DIR/user_activity/utmp.raw 2> /dev/null
        who -a /var/run/utmp 1> $OUTPUT_DIR/user_activity/who-utmp.txt 2> /dev/null
        who -H 1> $OUTPUT_DIR/user_activity/who-header.txt 2> /dev/null
        who -q 1> $OUTPUT_DIR/user_activity/who-count.txt 2> /dev/null
    fi
    if [ -f /var/log/lastlog ]; then
        cp /var/log/lastlog $OUTPUT_DIR/user_activity/lastlog.raw 2> /dev/null
        lastlog 1> $OUTPUT_DIR/user_activity/lastlog.txt 2> /dev/null
        lastlog -u 0-99999 1> $OUTPUT_DIR/user_activity/lastlog-all-users.txt 2> /dev/null
        lastlog -t 30 1> $OUTPUT_DIR/user_activity/lastlog-last-30-days.txt 2> /dev/null
    fi
	
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
	lastb > $OUTPUT_DIR/user_activity/lastb_failed_logins.txt
	journalctl -u sshd | grep -i failed > $OUTPUT_DIR/user_activity/journactl_sshd_ssh_failures.txt
elif [ $PLATFORM = "solaris" ]
then
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
    if [ -f /var/adm/loginlog ]; then
        cp /var/adm/loginlog $OUTPUT_DIR/user_activity/loginlog.raw 2> /dev/null
    fi
    logins -x 1> $OUTPUT_DIR/user_activity/logins-extended.txt 2> /dev/null
    logins -p 1> $OUTPUT_DIR/user_activity/logins-passwordless.txt 2> /dev/null
    w 1> $OUTPUT_DIR/user_activity/w-current-users.txt 2> /dev/null
    who -a 1> $OUTPUT_DIR/user_activity/who-all.txt 2> /dev/null
elif [ $PLATFORM = "aix" ]
then
    if [ -f /var/adm/wtmp ]; then
        cp /var/adm/wtmp $OUTPUT_DIR/user_activity/wtmp.raw 2> /dev/null
        last -f /var/adm/wtmp 1> $OUTPUT_DIR/user_activity/last-wtmp.txt 2> /dev/null
    fi
    if [ -f /etc/security/lastlog ]; then
        cp /etc/security/lastlog $OUTPUT_DIR/user_activity/lastlog.raw 2> /dev/null
        lsuser -f ALL 1> $OUTPUT_DIR/user_activity/lsuser-all.txt 2> /dev/null
    fi
    if [ -f /etc/security/failedlogin ]; then
        cp /etc/security/failedlogin $OUTPUT_DIR/user_activity/failedlogin.raw 2> /dev/null
        who /etc/security/failedlogin 1> $OUTPUT_DIR/user_activity/who-failedlogin.txt 2> /dev/null
    fi
    lsuser -a time_last_login unsuccessful_login_count ALL 1> $OUTPUT_DIR/user_activity/user_login_attrs.txt 2> /dev/null
    w 1> $OUTPUT_DIR/user_activity/w-current-users.txt 2> /dev/null
    who -a 1> $OUTPUT_DIR/user_activity/who-all.txt 2> /dev/null
elif [ $PLATFORM = "mac" ]
then
    if [ -f /var/log/wtmp ]; then
        cp /var/log/wtmp $OUTPUT_DIR/user_activity/wtmp.raw 2> /dev/null
        last 1> $OUTPUT_DIR/user_activity/last.txt 2> /dev/null
    fi
    if [ -f /var/log/lastlog ]; then
        cp /var/log/lastlog $OUTPUT_DIR/user_activity/lastlog.raw 2> /dev/null
        lastlog 1> $OUTPUT_DIR/user_activity/lastlog.txt 2> /dev/null
    fi
    log show --predicate 'process == "loginwindow"' --last 7d 1> $OUTPUT_DIR/user_activity/loginwindow-7days.txt 2> /dev/null
    log show --predicate 'eventMessage contains "Authentication"' --last 7d 1> $OUTPUT_DIR/user_activity/authentication-7days.txt 2> /dev/null
    log show --predicate 'subsystem == "com.apple.securityd"' --last 7d 1> $OUTPUT_DIR/user_activity/securityd-7days.txt 2> /dev/null
    log show --predicate 'process == "sudo"' --last 7d 1> $OUTPUT_DIR/user_activity/sudo-7days.txt 2> /dev/null
    w 1> $OUTPUT_DIR/user_activity/w-current-users.txt 2> /dev/null
    who -a 1> $OUTPUT_DIR/user_activity/who-all.txt 2> /dev/null
    ac -p 1> $OUTPUT_DIR/user_activity/ac-user-connect-time.txt 2> /dev/null
elif [ $PLATFORM = "android" ]
then
    dumpsys user 1> $OUTPUT_DIR/user_activity/android-user-state.txt 2> /dev/null
    dumpsys account 1> $OUTPUT_DIR/user_activity/android-accounts.txt 2> /dev/null
fi

mkdir $OUTPUT_DIR/user_activity/ssh_logs 2> /dev/null
mkdir $OUTPUT_DIR/user_activity/ssh_keys 2> /dev/null

if [ -f /var/log/auth.log ]; then
    grep -i ssh /var/log/auth.log 1> $OUTPUT_DIR/user_activity/ssh_logs/auth-ssh.txt 2> /dev/null
    grep -i "Accepted\|Failed\|Invalid" /var/log/auth.log 1> $OUTPUT_DIR/user_activity/ssh_logs/auth-login-attempts.txt 2> /dev/null
    grep "Accepted publickey\|Accepted password" /var/log/auth.log 1> $OUTPUT_DIR/user_activity/ssh_logs/auth-successful-ssh.txt 2> /dev/null
fi
if [ -f /var/log/secure ]; then
    grep -i ssh /var/log/secure 1> $OUTPUT_DIR/user_activity/ssh_logs/secure-ssh.txt 2> /dev/null
    grep -i "Accepted\|Failed\|Invalid" /var/log/secure 1> $OUTPUT_DIR/user_activity/ssh_logs/secure-login-attempts.txt 2> /dev/null
    grep "Accepted publickey\|Accepted password" /var/log/secure 1> $OUTPUT_DIR/user_activity/ssh_logs/secure-successful-ssh.txt 2> /dev/null
fi
if [ -f /var/log/messages ]; then
    grep -i "sshd\|authentication" /var/log/messages 1> $OUTPUT_DIR/user_activity/ssh_logs/messages-ssh.txt 2> /dev/null
fi

ls -la /etc/ssh/ssh_host_* 1> $OUTPUT_DIR/user_activity/ssh_logs/ssh_host_keys_list.txt 2> /dev/null

for keyfile in /etc/ssh/ssh_host_*.pub
do
    if [ -f "$keyfile" ]; then
        keyname=`basename $keyfile`
        ssh-keygen -lf "$keyfile" 1>> $OUTPUT_DIR/user_activity/ssh_logs/ssh_host_key_fingerprints.txt 2> /dev/null
    fi
done

if [ -f /etc/passwd ]; then
    cat /etc/passwd | while IFS=: read username x uid gid gecos homedir shell
    do
        if [ $uid -ge 500 -o $uid -eq 0 ] && [ -d "$homedir" ]; then
            if [ -d "$homedir/.ssh" ]; then
                user_ssh_dir="$OUTPUT_DIR/user_activity/ssh_keys/$username"
                mkdir -p $user_ssh_dir 2> /dev/null
                
                ls -la "$homedir/.ssh/" 1> "$user_ssh_dir/ssh_directory_listing.txt" 2> /dev/null
                
                if [ -f "$homedir/.ssh/authorized_keys" ]; then
                    cp "$homedir/.ssh/authorized_keys" "$user_ssh_dir/authorized_keys" 2> /dev/null
                    ssh-keygen -lf "$homedir/.ssh/authorized_keys" 1> "$user_ssh_dir/authorized_keys_fingerprints.txt" 2> /dev/null
                fi
                if [ -f "$homedir/.ssh/authorized_keys2" ]; then
                    cp "$homedir/.ssh/authorized_keys2" "$user_ssh_dir/authorized_keys2" 2> /dev/null
                    ssh-keygen -lf "$homedir/.ssh/authorized_keys2" 1> "$user_ssh_dir/authorized_keys2_fingerprints.txt" 2> /dev/null
                fi
                
                if [ -f "$homedir/.ssh/known_hosts" ]; then
                    cp "$homedir/.ssh/known_hosts" "$user_ssh_dir/known_hosts" 2> /dev/null
                    wc -l "$homedir/.ssh/known_hosts" 1> "$user_ssh_dir/known_hosts_count.txt" 2> /dev/null
                fi
                
                for pubkey in "$homedir/.ssh/"*.pub
                do
                    if [ -f "$pubkey" ]; then
                        pubkeyname=`basename "$pubkey"`
                        cp "$pubkey" "$user_ssh_dir/$pubkeyname" 2> /dev/null
                        ssh-keygen -lf "$pubkey" 1> "$user_ssh_dir/${pubkeyname}_fingerprint.txt" 2> /dev/null
                    fi
                done
                
                if [ -f "$homedir/.ssh/config" ]; then
                    cp "$homedir/.ssh/config" "$user_ssh_dir/ssh_config" 2> /dev/null
                fi
            fi
        fi
    done
fi

mkdir $OUTPUT_DIR/user_activity/shell_history 2> /dev/null

if [ -f /etc/passwd ]; then
    cat /etc/passwd | while IFS=: read username x uid gid gecos homedir shell
    do
        if [ $uid -ge 500 -o $uid -eq 0 ] && [ -d "$homedir" ]; then
            user_history_dir="$OUTPUT_DIR/user_activity/shell_history/$username"
            mkdir $user_history_dir 2> /dev/null
            
            for history_file in .bash_history .sh_history .zsh_history .ksh_history .history .ash_history .dash_history
            do
                if [ -f "$homedir/$history_file" ]; then
                    cp "$homedir/$history_file" "$user_history_dir/$history_file" 2> /dev/null
                    cat "$homedir/$history_file" 1> "$user_history_dir/${history_file}.txt" 2> /dev/null
                    ls -la "$homedir/$history_file" 1> "$user_history_dir/${history_file}.stats" 2> /dev/null
                    echo "=== Command Frequency ===" > "$user_history_dir/${history_file}.frequency"
                    cat "$homedir/$history_file" 2> /dev/null | sed 's/^[ \t]*//' | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -50 >> "$user_history_dir/${history_file}.frequency" 2> /dev/null
                fi
            done
            
            for config_file in .bashrc .bash_profile .profile .zshrc .kshrc .bash_logout .zprofile .zshenv
            do
                if [ -f "$homedir/$config_file" ]; then
                    grep -i "history\|HIST" "$homedir/$config_file" 1> "$user_history_dir/${config_file}_history_settings.txt" 2> /dev/null
                    grep -i "alias\|function" "$homedir/$config_file" 1> "$user_history_dir/${config_file}_aliases_functions.txt" 2> /dev/null
                fi
            done
            
            if [ -d "$homedir/.local/share" ]; then
                find "$homedir/.local/share" -name "*recent*" -o -name "*history*" 2> /dev/null | head -20 | while read recent_file
                do
                    relative_path=`echo $recent_file | sed "s|$homedir/||"`
                    mkdir -p "$user_history_dir/`dirname $relative_path`" 2> /dev/null
                    cp "$recent_file" "$user_history_dir/$relative_path" 2> /dev/null
                done
            fi
            
            if [ -f "$homedir/.python_history" ]; then
                cp "$homedir/.python_history" "$user_history_dir/python_history" 2> /dev/null
            fi
            if [ -d "$homedir/.ipython" ]; then
                find "$homedir/.ipython" -name "*history*" -type f 2> /dev/null | head -10 | while read pyhistory
                do
                    pyname=`basename "$pyhistory"`
                    cp "$pyhistory" "$user_history_dir/ipython_$pyname" 2> /dev/null
                done
            fi
            
            if [ -f "$homedir/.mysql_history" ]; then
                cp "$homedir/.mysql_history" "$user_history_dir/mysql_history" 2> /dev/null
            fi
            
            if [ -f "$homedir/.lesshst" ]; then
                cp "$homedir/.lesshst" "$user_history_dir/less_history" 2> /dev/null
            fi
            
            ls -la $homedir/.*history* 1> "$user_history_dir/history_files_list.txt" 2> /dev/null
        fi
    done
fi

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

if [ -d /var/run/sudo ]; then
    ls -la /var/run/sudo/ 1> $OUTPUT_DIR/user_activity/sudo_logs/sudo_timestamps.txt 2> /dev/null
    find /var/run/sudo -type f 2> /dev/null | while read tsfile
    do
        ls -la "$tsfile" 1>> $OUTPUT_DIR/user_activity/sudo_logs/sudo_timestamp_details.txt 2> /dev/null
    done
fi
if [ -d /var/db/sudo ]; then
    ls -la /var/db/sudo/ 1> $OUTPUT_DIR/user_activity/sudo_logs/sudo_db_timestamps.txt 2> /dev/null
fi

if [ -f /etc/sudoers ]; then
    ls -la /etc/sudoers 1> $OUTPUT_DIR/user_activity/sudo_logs/sudoers_stats.txt 2> /dev/null
    visudo -c 1>> $OUTPUT_DIR/user_activity/sudo_logs/sudoers_syntax_check.txt 2>&1
fi

sudo -l 1> $OUTPUT_DIR/user_activity/sudo_logs/current_user_sudo_list.txt 2> /dev/null
sudo -ll 1> $OUTPUT_DIR/user_activity/sudo_logs/current_user_sudo_list_long.txt 2> /dev/null

if [ -f /var/log/sulog ]; then
    cp /var/log/sulog $OUTPUT_DIR/user_activity/sulog 2> /dev/null
fi
if [ -f /var/adm/sulog ]; then
    cp /var/adm/sulog $OUTPUT_DIR/user_activity/sulog 2> /dev/null
fi
for log in /var/log/auth.log /var/log/secure /var/log/messages
do
    if [ -f "$log" ]; then
        logname=`basename "$log"`
        grep -i "su\[" "$log" 1> $OUTPUT_DIR/user_activity/su_events_${logname}.txt 2> /dev/null
        grep "su: " "$log" 1>> $OUTPUT_DIR/user_activity/su_events_${logname}.txt 2> /dev/null
    fi
done

mkdir $OUTPUT_DIR/user_activity/pam_config 2> /dev/null

for pamfile in system-auth common-auth login sshd sudo su
do
    if [ -f "/etc/pam.d/$pamfile" ]; then
        cp "/etc/pam.d/$pamfile" "$OUTPUT_DIR/user_activity/pam_config/pam_${pamfile}" 2> /dev/null
    fi
done

if [ -f "/etc/security/pwquality.conf" ]; then
    cp "/etc/security/pwquality.conf" "$OUTPUT_DIR/user_activity/pam_config/" 2> /dev/null
fi

if [ -f "/etc/login.defs" ]; then
    grep -E "PASS_|LOGIN_|FAIL_|SU_" /etc/login.defs 1> $OUTPUT_DIR/user_activity/pam_config/login_defs_extract.txt 2> /dev/null
fi

if [ -f "/etc/krb5.conf" -o -f "/etc/ldap.conf" ]; then
    mkdir $OUTPUT_DIR/user_activity/auth_config 2> /dev/null
    
    if [ -f "/etc/krb5.conf" ]; then
        cp /etc/krb5.conf $OUTPUT_DIR/user_activity/auth_config/ 2> /dev/null
        # Current tickets
        klist 1> $OUTPUT_DIR/user_activity/auth_config/klist_current.txt 2> /dev/null
    fi
    
    if [ -f "/etc/ldap.conf" ]; then
        cp /etc/ldap.conf $OUTPUT_DIR/user_activity/auth_config/ 2> /dev/null 2> /dev/null
    fi
fi

if [ $PLATFORM = "linux" ]; then
    if [ -x /usr/bin/journalctl ]; then
        journalctl _COMM=sshd --since "90 days ago" 1> $OUTPUT_DIR/user_activity/journalctl-sshd-90days.txt 2> /dev/null
        journalctl _COMM=sudo --since "90 days ago" 1> $OUTPUT_DIR/user_activity/journalctl-sudo-90days.txt 2> /dev/null
        journalctl _COMM=su --since "90 days ago" 1> $OUTPUT_DIR/user_activity/journalctl-su-90days.txt 2> /dev/null
        journalctl _COMM=login --since "90 days ago" 1> $OUTPUT_DIR/user_activity/journalctl-login-90days.txt 2> /dev/null
        loginctl list-sessions 1> $OUTPUT_DIR/user_activity/loginctl-sessions.txt 2> /dev/null
        loginctl list-users 1> $OUTPUT_DIR/user_activity/loginctl-users.txt 2> /dev/null
        loginctl list-sessions --no-legend 2> /dev/null | awk '{print $1}' | while read session
        do
            echo "=== Session $session ===" >> $OUTPUT_DIR/user_activity/loginctl-session-details.txt
            loginctl show-session $session >> $OUTPUT_DIR/user_activity/loginctl-session-details.txt 2> /dev/null
        done
    fi
    if [ -d /var/log/pam ]; then
        cp -R /var/log/pam $OUTPUT_DIR/user_activity/ 2> /dev/null
    fi
    if [ -x "$(command -v faillock)" ]; then
        faillock 1> $OUTPUT_DIR/user_activity/faillock-status.txt 2> /dev/null
    fi
    if [ -x "$(command -v pam_tally2)" ]; then
        pam_tally2 1> $OUTPUT_DIR/user_activity/pam_tally2-status.txt 2> /dev/null
    fi
elif [ $PLATFORM = "mac" ]; then
    dscl . -list /Users | grep -v '^_' | while read username
    do
        echo "User: $username" 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
        dscl . -read /Users/$username LastLoginTime 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
        dscl . -read /Users/$username accountPolicyData 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
        dscl . -read /Users/$username PasswordPolicyOptions 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
        echo "---" 1>> $OUTPUT_DIR/user_activity/macos_user_info.txt 2> /dev/null
    done
    # FileVault users
    fdesetup list 1> $OUTPUT_DIR/user_activity/filevault_users.txt 2> /dev/null
elif [ $PLATFORM = "solaris" ]; then
    # Solaris specific
    if [ -f /var/log/authlog ]; then
        cp /var/log/authlog $OUTPUT_DIR/user_activity/ 2> /dev/null
    fi
    logins -x 1> $OUTPUT_DIR/user_activity/logins-extended.txt 2> /dev/null
    # Role-based access
    roles 1> $OUTPUT_DIR/user_activity/roles.txt 2> /dev/null
    auths 1> $OUTPUT_DIR/user_activity/auths.txt 2> /dev/null
fi

echo "=== User Activity Collection Summary ===" 1> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "Platform: $PLATFORM" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "Collection Date: `date`" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "Currently logged in users:" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
who | wc -l 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "User accounts with UID >= 500 or UID 0:" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
awk -F: '$3 >= 500 || $3 == 0 {print $1}' /etc/passwd 2> /dev/null | sort 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "SSH Keys Found:" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
find $OUTPUT_DIR/user_activity/ssh_keys -name "*.pub" -o -name "authorized_keys*" 2> /dev/null | wc -l 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "Shell History Files Found:" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
find $OUTPUT_DIR/user_activity/shell_history -name "*history*" -type f 2> /dev/null | wc -l 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
echo "" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
if [ -f /var/log/btmp ]; then
    echo "Recent Failed Login Attempts:" 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
    lastb -n 5 2> /dev/null | head -6 1>> $OUTPUT_DIR/user_activity/summary.txt 2> /dev/null
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

echo "  ${COL_ENTRY}>${RESET} Unowned Files Detection"
mkdir $OUTPUT_DIR/general/unowned_files 2> /dev/null

find /etc /usr /var /opt /home /root /tmp -xdev -nouser -ls 2> /dev/null | head -1000 > $OUTPUT_DIR/general/unowned_files/nouser_files.txt 2> /dev/null
find /etc /usr /var /opt /home /root /tmp -xdev -nogroup -ls 2> /dev/null | head -1000 > $OUTPUT_DIR/general/unowned_files/nogroup_files.txt 2> /dev/null
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev \( -perm -4000 -o -perm -2000 \) \( -nouser -o -nogroup \) -ls 2> /dev/null > $OUTPUT_DIR/general/unowned_files/unowned_suid_sgid.txt 2> /dev/null

# Get list of valid UIDs
cut -d: -f3 /etc/passwd | sort -n > $OUTPUT_DIR/general/unowned_files/valid_uids.txt 2> /dev/null
# Find files owned by UIDs not in passwd file (limited search)
find /etc /usr/bin /usr/sbin -xdev -type f -ls 2> /dev/null | head -5000 | awk '{print $5, $0}' | while read uid rest; do
    grep -q "^${uid}$" $OUTPUT_DIR/general/unowned_files/valid_uids.txt || echo "$uid $rest" >> $OUTPUT_DIR/general/unowned_files/invalid_uid_files.txt
done

find /etc /usr /var /opt -xdev -type f -perm -0002 \( -nouser -o -nogroup \) -ls 2> /dev/null | head -500 > $OUTPUT_DIR/general/unowned_files/world_writable_unowned.txt 2> /dev/null
echo "Files with no user owner: $(wc -l < $OUTPUT_DIR/general/unowned_files/nouser_files.txt 2> /dev/null || echo 0)" > $OUTPUT_DIR/general/unowned_files/summary.txt
echo "Files with no group owner: $(wc -l < $OUTPUT_DIR/general/unowned_files/nogroup_files.txt 2> /dev/null || echo 0)" >> $OUTPUT_DIR/general/unowned_files/summary.txt
echo "Unowned SUID/SGID files: $(wc -l < $OUTPUT_DIR/general/unowned_files/unowned_suid_sgid.txt 2> /dev/null || echo 0)" >> $OUTPUT_DIR/general/unowned_files/summary.txt
echo "World-writable unowned: $(wc -l < $OUTPUT_DIR/general/unowned_files/world_writable_unowned.txt 2> /dev/null || echo 0)" >> $OUTPUT_DIR/general/unowned_files/summary.txt

echo "  ${COL_ENTRY}>${RESET} Dead Process Detection"
mkdir $OUTPUT_DIR/general/dead_processes 2> /dev/null

# Find processes where the executable has been deleted
ls -1 /proc 2> /dev/null | grep '^[0-9]*$' | while read pid; do
    if [ -r "/proc/$pid/exe" ]; then
        exe_link=$(readlink "/proc/$pid/exe" 2> /dev/null)
        if echo "$exe_link" | grep -q "(deleted)"; then
            # Get process info
            if [ -r "/proc/$pid/cmdline" ]; then
                echo "PID: $pid" >> $OUTPUT_DIR/general/dead_processes/deleted_executables.txt
                echo "Exe: $exe_link" >> $OUTPUT_DIR/general/dead_processes/deleted_executables.txt
                tr '\0' ' ' < "/proc/$pid/cmdline" >> $OUTPUT_DIR/general/dead_processes/deleted_executables.txt 2> /dev/null
                echo "---" >> $OUTPUT_DIR/general/dead_processes/deleted_executables.txt
                
                # Try to get process owner
                stat_info=$(stat -c "%U" "/proc/$pid" 2> /dev/null)
                echo "Owner: $stat_info" >> $OUTPUT_DIR/general/dead_processes/deleted_executables.txt
                echo "========================================" >> $OUTPUT_DIR/general/dead_processes/deleted_executables.txt
            fi
        fi
    fi
done

# For each process with deleted executable, save memory maps
mkdir $OUTPUT_DIR/general/dead_processes/maps 2> /dev/null
ls -1 /proc 2> /dev/null | grep '^[0-9]*$' | while read pid; do
    if [ -r "/proc/$pid/exe" ]; then
        exe_link=$(readlink "/proc/$pid/exe" 2> /dev/null)
        if echo "$exe_link" | grep -q "(deleted)"; then
            if [ -r "/proc/$pid/maps" ]; then
                cp "/proc/$pid/maps" "$OUTPUT_DIR/general/dead_processes/maps/pid_${pid}_maps.txt" 2> /dev/null
                
                # Also get memory regions info (if available)
                cp "/proc/$pid/smaps" "$OUTPUT_DIR/general/dead_processes/maps/pid_${pid}_smaps.txt" 2> /dev/null
            fi
        fi
    fi
done

# Extract strings from deleted process memory (limited to avoid huge dumps)
mkdir $OUTPUT_DIR/general/dead_processes/memory_strings 2> /dev/null
ls -1 /proc 2> /dev/null | grep '^[0-9]*$' | while read pid; do
    if [ -r "/proc/$pid/exe" ]; then
        exe_link=$(readlink "/proc/$pid/exe" 2> /dev/null)
        if echo "$exe_link" | grep -q "(deleted)"; then
            # Only if we can read the mem file
            if [ -r "/proc/$pid/mem" ] && [ -r "/proc/$pid/maps" ]; then
                # Extract strings from stack and heap regions only (safer)
                grep -E "stack|heap" "/proc/$pid/maps" 2> /dev/null | head -5 | while read line; do
                    start_addr=$(echo "$line" | awk '{print $1}' | cut -d'-' -f1)
                    end_addr=$(echo "$line" | awk '{print $1}' | cut -d'-' -f2)
                    # Convert hex to decimal for dd
                    start_dec=$(printf "%d" "0x$start_addr" 2> /dev/null)
                    end_dec=$(printf "%d" "0x$end_addr" 2> /dev/null)
                    size=$((end_dec - start_dec))
                    
                    # Limit size to 10MB per region
                    if [ "$size" -gt 0 ] && [ "$size" -lt 10485760 ]; then
                        dd if="/proc/$pid/mem" bs=1 skip="$start_dec" count="$size" 2> /dev/null | \
                        strings -n 8 | head -1000 >> "$OUTPUT_DIR/general/dead_processes/memory_strings/pid_${pid}_strings.txt" 2> /dev/null
                    fi
                done
            fi
        fi
    fi
done

# Check for open file descriptors pointing to deleted files
mkdir $OUTPUT_DIR/general/dead_processes/deleted_fds 2> /dev/null
ls -1 /proc 2> /dev/null | grep '^[0-9]*$' | while read pid; do
    if [ -d "/proc/$pid/fd" ] && [ -r "/proc/$pid/fd" ]; then
        ls -la "/proc/$pid/fd/" 2> /dev/null | grep "(deleted)" > /dev/null
        if [ $? -eq 0 ]; then
            echo "PID: $pid" >> $OUTPUT_DIR/general/dead_processes/deleted_fds/deleted_file_descriptors.txt
            ls -la "/proc/$pid/fd/" 2> /dev/null | grep "(deleted)" >> $OUTPUT_DIR/general/dead_processes/deleted_fds/deleted_file_descriptors.txt
            echo "---" >> $OUTPUT_DIR/general/dead_processes/deleted_fds/deleted_file_descriptors.txt
        fi
    fi
done

# Look for processes trying to hide
mkdir $OUTPUT_DIR/general/dead_processes/suspicious 2> /dev/null

# Processes with all numeric names (common hiding technique)
ps aux | awk '$11 ~ /^[0-9]+$/ {print}' > $OUTPUT_DIR/general/dead_processes/suspicious/numeric_process_names.txt 2> /dev/null

# Processes with very short names
ps aux | awk 'length($11) <= 2 && $11 !~ /^(ps|ls|cp|mv|rm|sh|vi)$/ {print}' > $OUTPUT_DIR/general/dead_processes/suspicious/short_process_names.txt 2> /dev/null

# Kernel threads impersonation check (user-space process with [] in name)
ps aux | grep -E "^\[.*\]$" | grep -v " 0:" > $OUTPUT_DIR/general/dead_processes/suspicious/fake_kernel_threads.txt 2> /dev/null

# Get environment variables for processes with deleted executables
ls -1 /proc 2> /dev/null | grep '^[0-9]*$' | while read pid; do
    if [ -r "/proc/$pid/exe" ]; then
        exe_link=$(readlink "/proc/$pid/exe" 2> /dev/null)
        if echo "$exe_link" | grep -q "(deleted)"; then
            if [ -r "/proc/$pid/environ" ]; then
                echo "PID: $pid" >> $OUTPUT_DIR/general/dead_processes/deleted_process_environ.txt
                tr '\0' '\n' < "/proc/$pid/environ" 2> /dev/null >> $OUTPUT_DIR/general/dead_processes/deleted_process_environ.txt
                echo "========================================" >> $OUTPUT_DIR/general/dead_processes/deleted_process_environ.txt
            fi
        fi
    fi
done

cat /proc/sys/kernel/core_pattern > $OUTPUT_DIR/general/dead_processes/core_pattern.txt 2> /dev/null
ulimit -c > $OUTPUT_DIR/general/dead_processes/core_ulimit.txt 2> /dev/null

find / -name "core" -o -name "core.*" -type f 2> /dev/null | head -50 > $OUTPUT_DIR/general/dead_processes/existing_core_dumps.txt 2> /dev/null

proc_count=$(grep -c "^PID:" $OUTPUT_DIR/general/dead_processes/deleted_executables.txt 2> /dev/null || echo 0)
echo "Processes with deleted executables: $proc_count" > $OUTPUT_DIR/general/dead_processes/summary.txt
fd_count=$(grep -c "^PID:" $OUTPUT_DIR/general/dead_processes/deleted_fds/deleted_file_descriptors.txt 2> /dev/null || echo 0)
echo "Processes with deleted file descriptors: $fd_count" >> $OUTPUT_DIR/general/dead_processes/summary.txt
core_count=$(wc -l < $OUTPUT_DIR/general/dead_processes/existing_core_dumps.txt 2> /dev/null || echo 0)
echo "Core dumps found: $core_count" >> $OUTPUT_DIR/general/dead_processes/summary.txt

echo "  ${COL_ENTRY}>${RESET} Security frameworks and policies"
mkdir $OUTPUT_DIR/security_frameworks 2> /dev/null

if [ $PLATFORM = "linux" -o $PLATFORM = "generic" ]
then
    # SELinux collection
    mkdir $OUTPUT_DIR/security_frameworks/selinux 2> /dev/null
    
    # Basic SELinux status
    if [ -x /usr/sbin/getenforce ]; then
        getenforce 1> $OUTPUT_DIR/security_frameworks/selinux/getenforce.txt 2> /dev/null
    fi
    if [ -x /usr/sbin/sestatus ]; then
        sestatus 1> $OUTPUT_DIR/security_frameworks/selinux/sestatus.txt 2> /dev/null
        sestatus -v 1> $OUTPUT_DIR/security_frameworks/selinux/sestatus-verbose.txt 2> /dev/null
        sestatus -b 1> $OUTPUT_DIR/security_frameworks/selinux/sestatus-booleans.txt 2> /dev/null
    fi
    
    # SELinux configuration files
    if [ -f /etc/selinux/config ]; then
        cp /etc/selinux/config $OUTPUT_DIR/security_frameworks/selinux/ 2> /dev/null
    fi
    if [ -f /etc/sysconfig/selinux ]; then
        cp /etc/sysconfig/selinux $OUTPUT_DIR/security_frameworks/selinux/sysconfig-selinux 2> /dev/null
    fi
    
    # SELinux policy information
    if [ -x /usr/sbin/semodule ]; then
        semodule -l 1> $OUTPUT_DIR/security_frameworks/selinux/semodule-list.txt 2> /dev/null
    fi
    if [ -x /usr/sbin/semanage ]; then
        # Export current policy
        semanage export 1> $OUTPUT_DIR/security_frameworks/selinux/semanage-export.txt 2> /dev/null
        # List various SELinux configurations
        semanage login -l 1> $OUTPUT_DIR/security_frameworks/selinux/semanage-login.txt 2> /dev/null
        semanage user -l 1> $OUTPUT_DIR/security_frameworks/selinux/semanage-user.txt 2> /dev/null
        semanage port -l 1> $OUTPUT_DIR/security_frameworks/selinux/semanage-port.txt 2> /dev/null
        semanage fcontext -l 1> $OUTPUT_DIR/security_frameworks/selinux/semanage-fcontext.txt 2> /dev/null
        semanage boolean -l 1> $OUTPUT_DIR/security_frameworks/selinux/semanage-boolean.txt 2> /dev/null
        semanage node -l 1> $OUTPUT_DIR/security_frameworks/selinux/semanage-node.txt 2> /dev/null
        semanage interface -l 1> $OUTPUT_DIR/security_frameworks/selinux/semanage-interface.txt 2> /dev/null
    fi
    
    # Get current SELinux contexts
    if [ -x /usr/bin/id ]; then
        id -Z 1> $OUTPUT_DIR/security_frameworks/selinux/current-context.txt 2> /dev/null
    fi
    ps auxZ 1> $OUTPUT_DIR/security_frameworks/selinux/ps-contexts.txt 2> /dev/null
    ls -laZ / 1> $OUTPUT_DIR/security_frameworks/selinux/root-contexts.txt 2> /dev/null
    
    # SELinux denials and audit logs
    if [ -x /usr/bin/ausearch ]; then
        ausearch -m avc -ts recent 1> $OUTPUT_DIR/security_frameworks/selinux/avc-denials-recent.txt 2> /dev/null
    fi
    if [ -f /var/log/audit/audit.log ]; then
        grep -i avc /var/log/audit/audit.log | tail -1000 1> $OUTPUT_DIR/security_frameworks/selinux/avc-denials-log.txt 2> /dev/null
    fi
    
    # Check loaded policy
    if [ -f /sys/fs/selinux/policy ]; then
        ls -la /sys/fs/selinux/policy 1> $OUTPUT_DIR/security_frameworks/selinux/loaded-policy-info.txt 2> /dev/null
    fi
    
    # AppArmor collection
    mkdir $OUTPUT_DIR/security_frameworks/apparmor 2> /dev/null
    # AppArmor status
    if [ -x /usr/sbin/aa-status ]; then
        aa-status 1> $OUTPUT_DIR/security_frameworks/apparmor/aa-status.txt 2> /dev/null
    fi
    if [ -x /usr/sbin/apparmor_status ]; then
        apparmor_status 1> $OUTPUT_DIR/security_frameworks/apparmor/apparmor-status.txt 2> /dev/null
    fi
    
    # AppArmor configuration
    if [ -d /etc/apparmor ]; then
        cp -R /etc/apparmor $OUTPUT_DIR/security_frameworks/apparmor/etc-apparmor 2> /dev/null
    fi
    if [ -d /etc/apparmor.d ]; then
        mkdir $OUTPUT_DIR/security_frameworks/apparmor/profiles 2> /dev/null
        cp -R /etc/apparmor.d/* $OUTPUT_DIR/security_frameworks/apparmor/profiles/ 2> /dev/null
        # List profiles
        ls -la /etc/apparmor.d/ 1> $OUTPUT_DIR/security_frameworks/apparmor/profiles-list.txt 2> /dev/null
    fi
    
    # Loaded AppArmor profiles
    if [ -f /sys/kernel/security/apparmor/profiles ]; then
        cat /sys/kernel/security/apparmor/profiles 1> $OUTPUT_DIR/security_frameworks/apparmor/loaded-profiles.txt 2> /dev/null
    fi
    
    # AppArmor kernel parameters
    if [ -d /sys/module/apparmor/parameters ]; then
        for param in /sys/module/apparmor/parameters/*
        do
            echo "`basename $param` = `cat $param 2> /dev/null`" 1>> $OUTPUT_DIR/security_frameworks/apparmor/kernel-parameters.txt 2> /dev/null
        done
    fi
    
    # Check for AppArmor denials
    if [ -f /var/log/audit/audit.log ]; then
        grep -i apparmor /var/log/audit/audit.log | 1> $OUTPUT_DIR/security_frameworks/apparmor/denials-audit.txt 2> /dev/null
    fi
    if [ -f /var/log/kern.log ]; then
        grep -i apparmor /var/log/kern.log | 1> $OUTPUT_DIR/security_frameworks/apparmor/denials-kern.txt 2> /dev/null
    fi
    
    # grsecurity/PaX collection
    if [ -f /proc/sys/kernel/grsecurity/grsec_lock ]; then
		mkdir $OUTPUT_DIR/security_frameworks/grsecurity 2> /dev/null
        echo "grsecurity detected" > $OUTPUT_DIR/security_frameworks/grsecurity/detected.txt
        # Collect grsec settings (if readable)
        find /proc/sys/kernel/grsecurity -type f 2> /dev/null | while read grsec_file
        do
            echo "$grsec_file = `cat $grsec_file 2> /dev/null || echo 'unreadable'`" 1>> $OUTPUT_DIR/security_frameworks/grsecurity/settings.txt 2> /dev/null
        done
    fi
    
    # Check for PaX flags
    if [ -x /sbin/paxctl ]; then
        paxctl -v 1> $OUTPUT_DIR/security_frameworks/grsecurity/paxctl-version.txt 2> /dev/null
    fi
    
    # SMACK collection
    if [ -d /sys/fs/smackfs ]; then
		mkdir $OUTPUT_DIR/security_frameworks/smack 2> /dev/null
        echo "SMACK detected" > $OUTPUT_DIR/security_frameworks/smack/detected.txt
        ls -la /sys/fs/smackfs/ 1> $OUTPUT_DIR/security_frameworks/smack/smackfs-contents.txt 2> /dev/null
        if [ -f /sys/fs/smackfs/load2 ]; then
            cat /sys/fs/smackfs/load2 1> $OUTPUT_DIR/security_frameworks/smack/loaded-rules.txt 2> /dev/null
        fi
    fi
    
    # TOMOYO collection
    mkdir $OUTPUT_DIR/security_frameworks/tomoyo 2> /dev/null
    if [ -d /sys/kernel/security/tomoyo ]; then
        echo "TOMOYO detected" > $OUTPUT_DIR/security_frameworks/tomoyo/detected.txt
        ls -la /sys/kernel/security/tomoyo/ 1> $OUTPUT_DIR/security_frameworks/tomoyo/kernel-interface.txt 2> /dev/null
    fi
    if [ -d /etc/tomoyo ]; then
        cp -R /etc/tomoyo $OUTPUT_DIR/security_frameworks/tomoyo/etc-tomoyo 2> /dev/null
    fi
    
    # Integrity Measurement Architecture (IMA)
    if [ -d /sys/kernel/security/ima ]; then
		mkdir $OUTPUT_DIR/security_frameworks/ima 2> /dev/null
        echo "IMA detected" > $OUTPUT_DIR/security_frameworks/ima/detected.txt
        for ima_file in /sys/kernel/security/ima/*
        do
            if [ -f "$ima_file" ]; then
                echo "=== `basename $ima_file` ===" >> $OUTPUT_DIR/security_frameworks/ima/measurements.txt
                cat "$ima_file" 2> /dev/null >> $OUTPUT_DIR/security_frameworks/ima/measurements.txt || echo "unreadable" >> $OUTPUT_DIR/security_frameworks/ima/measurements.txt
                echo "" >> $OUTPUT_DIR/security_frameworks/ima/measurements.txt
            fi
        done
    fi
    
    # Check security-related kernel parameters
    sysctl -a 2> /dev/null | grep -E "kernel.yama|kernel.kptr_restrict|kernel.dmesg_restrict|kernel.modules_disabled|kernel.unprivileged_|net.core.bpf_jit_harden|kernel.lockdown" 1> $OUTPUT_DIR/security_frameworks/security-sysctls.txt 2> /dev/null
    
elif [ $PLATFORM = "solaris" ]
then
    mkdir $OUTPUT_DIR/security_frameworks/solaris 2> /dev/null
    
    # Solaris Trusted Extensions
    if [ -x /usr/bin/tncfg ]; then
        echo "Trusted Extensions detected" > $OUTPUT_DIR/security_frameworks/solaris/trusted-extensions.txt
        tncfg list 1>> $OUTPUT_DIR/security_frameworks/solaris/trusted-extensions.txt 2> /dev/null
    fi
    
    # Basic Security Module (BSM) / Solaris Audit
    if [ -x /usr/sbin/auditconfig ]; then
        auditconfig -getpolicy 1> $OUTPUT_DIR/security_frameworks/solaris/audit-policy.txt 2> /dev/null
        auditconfig -getflags 1> $OUTPUT_DIR/security_frameworks/solaris/audit-flags.txt 2> /dev/null
        auditconfig -getnaflags 1> $OUTPUT_DIR/security_frameworks/solaris/audit-naflags.txt 2> /dev/null
    fi
    if [ -f /etc/security/audit_control ]; then
        cp /etc/security/audit_control $OUTPUT_DIR/security_frameworks/solaris/ 2> /dev/null
    fi
    if [ -f /etc/security/audit_class ]; then
        cp /etc/security/audit_class $OUTPUT_DIR/security_frameworks/solaris/ 2> /dev/null
    fi
    
    # Solaris privileges
    if [ -x /usr/bin/ppriv ]; then
        ppriv -l 1> $OUTPUT_DIR/security_frameworks/solaris/privileges-list.txt 2> /dev/null
        ppriv $$ 1> $OUTPUT_DIR/security_frameworks/solaris/current-privileges.txt 2> /dev/null
    fi
    
    # Solaris RBAC
    if [ -f /etc/security/exec_attr ]; then
        cp /etc/security/exec_attr $OUTPUT_DIR/security_frameworks/solaris/ 2> /dev/null
    fi
    if [ -f /etc/security/prof_attr ]; then
        cp /etc/security/prof_attr $OUTPUT_DIR/security_frameworks/solaris/ 2> /dev/null
    fi
    if [ -f /etc/user_attr ]; then
        cp /etc/user_attr $OUTPUT_DIR/security_frameworks/solaris/ 2> /dev/null
    fi
    
elif [ $PLATFORM = "aix" ]
then
    mkdir $OUTPUT_DIR/security_frameworks/aix 2> /dev/null
    
    # AIX Trusted Execution
    if [ -x /usr/sbin/trustchk ]; then
        trustchk -p ALL 1> $OUTPUT_DIR/security_frameworks/aix/trustchk-policy.txt 2> /dev/null
        trustchk -n ALL 1> $OUTPUT_DIR/security_frameworks/aix/trustchk-verify.txt 2> /dev/null
    fi
    
    # AIX Role Based Access Control
    if [ -f /etc/security/roles ]; then
        cp /etc/security/roles $OUTPUT_DIR/security_frameworks/aix/ 2> /dev/null
    fi
    if [ -f /etc/security/authorizations ]; then
        cp /etc/security/authorizations $OUTPUT_DIR/security_frameworks/aix/ 2> /dev/null
    fi
    if [ -f /etc/security/privcmds ]; then
        cp /etc/security/privcmds $OUTPUT_DIR/security_frameworks/aix/ 2> /dev/null
    fi
    
    # AIX security settings
    if [ -f /etc/security/limits ]; then
        cp /etc/security/limits $OUTPUT_DIR/security_frameworks/aix/ 2> /dev/null
    fi
    if [ -f /etc/security/login.cfg ]; then
        cp /etc/security/login.cfg $OUTPUT_DIR/security_frameworks/aix/ 2> /dev/null
    fi
    
    # List security attributes
    lssec -f /etc/security/user -s default -a 1> $OUTPUT_DIR/security_frameworks/aix/default-user-security.txt 2> /dev/null
    
elif [ $PLATFORM = "mac" ]
then
    mkdir $OUTPUT_DIR/security_frameworks/macos 2> /dev/null
    
    # System Integrity Protection (SIP)
    csrutil status 1> $OUTPUT_DIR/security_frameworks/macos/sip-status.txt 2> /dev/null
    
    # Gatekeeper
    spctl --status 1> $OUTPUT_DIR/security_frameworks/macos/gatekeeper-status.txt 2> /dev/null
    spctl --list 1> $OUTPUT_DIR/security_frameworks/macos/gatekeeper-rules.txt 2> /dev/null
    
    # FileVault
    fdesetup status 1> $OUTPUT_DIR/security_frameworks/macos/filevault-status.txt 2> /dev/null
    
    # Application Firewall
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 1> $OUTPUT_DIR/security_frameworks/macos/firewall-state.txt 2> /dev/null
    /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 1> $OUTPUT_DIR/security_frameworks/macos/firewall-apps.txt 2> /dev/null
    
    # Mandatory Access Control Framework
    if [ -f /etc/security/audit_control ]; then
        cp /etc/security/audit_control $OUTPUT_DIR/security_frameworks/macos/ 2> /dev/null
    fi
    
    # TCC (Transparency, Consent, and Control)
    if [ -f /Library/Application\ Support/com.apple.TCC/TCC.db ]; then
        echo "TCC database found at /Library/Application Support/com.apple.TCC/TCC.db" > $OUTPUT_DIR/security_frameworks/macos/tcc-location.txt
    fi
    
elif [ $PLATFORM = "hpux" ]
then
    mkdir $OUTPUT_DIR/security_frameworks/hpux 2> /dev/null
    
    # HP-UX Security Containment
    if [ -x /usr/sbin/compartments ]; then
        compartments -l 1> $OUTPUT_DIR/security_frameworks/hpux/compartments.txt 2> /dev/null
    fi
    
    # HP-UX RBAC
    if [ -f /etc/rbac/cmd_priv ]; then
        cp /etc/rbac/cmd_priv $OUTPUT_DIR/security_frameworks/hpux/ 2> /dev/null
    fi
    if [ -f /etc/rbac/role_auth ]; then
        cp /etc/rbac/role_auth $OUTPUT_DIR/security_frameworks/hpux/ 2> /dev/null
    fi
    
elif [ $PLATFORM = "android" ]
then
    mkdir $OUTPUT_DIR/security_frameworks/android 2> /dev/null
    
    # SELinux on Android
    getenforce 1> $OUTPUT_DIR/security_frameworks/android/selinux-status.txt 2> /dev/null
    
    # Android permissions
    pm list permissions -g -f 1> $OUTPUT_DIR/security_frameworks/android/permissions-groups.txt 2> /dev/null
    
    # Security properties
    getprop | grep -E "ro.secure|security|selinux|crypto" 1> $OUTPUT_DIR/security_frameworks/android/security-properties.txt 2> /dev/null
fi

# Check for security-related processes
ps aux | grep -E "selinux|apparmor|grsec|auditd" | grep -v grep 1> $OUTPUT_DIR/security_frameworks/security-processes.txt 2> /dev/null

# Create summary
echo "=== Security Frameworks Summary ===" > $OUTPUT_DIR/security_frameworks/summary.txt
echo "Platform: $PLATFORM" >> $OUTPUT_DIR/security_frameworks/summary.txt
echo "Collection Date: `date`" >> $OUTPUT_DIR/security_frameworks/summary.txt
echo "" >> $OUTPUT_DIR/security_frameworks/summary.txt

# Summary for Linux systems
if [ $PLATFORM = "linux" -o $PLATFORM = "generic" ]; then
    # SELinux status
    if [ -f $OUTPUT_DIR/security_frameworks/selinux/getenforce.txt ]; then
        SELINUX_STATUS=`cat $OUTPUT_DIR/security_frameworks/selinux/getenforce.txt 2> /dev/null`
        echo "SELinux: $SELINUX_STATUS" >> $OUTPUT_DIR/security_frameworks/summary.txt
    else
        echo "SELinux: Not installed" >> $OUTPUT_DIR/security_frameworks/summary.txt
    fi
    
    # AppArmor status
    if [ -f $OUTPUT_DIR/security_frameworks/apparmor/aa-status.txt ]; then
        APPARMOR_PROFILES=`grep -c "profiles are loaded" $OUTPUT_DIR/security_frameworks/apparmor/aa-status.txt 2> /dev/null || echo "0"`
        echo "AppArmor: Active ($APPARMOR_PROFILES profiles)" >> $OUTPUT_DIR/security_frameworks/summary.txt
    else
        echo "AppArmor: Not installed" >> $OUTPUT_DIR/security_frameworks/summary.txt
    fi
    
    # Other frameworks
    [ -f $OUTPUT_DIR/security_frameworks/grsecurity/detected.txt ] && echo "grsecurity: Detected" >> $OUTPUT_DIR/security_frameworks/summary.txt
    [ -f $OUTPUT_DIR/security_frameworks/smack/detected.txt ] && echo "SMACK: Detected" >> $OUTPUT_DIR/security_frameworks/summary.txt
    [ -f $OUTPUT_DIR/security_frameworks/tomoyo/detected.txt ] && echo "TOMOYO: Detected" >> $OUTPUT_DIR/security_frameworks/summary.txt
    [ -f $OUTPUT_DIR/security_frameworks/ima/detected.txt ] && echo "IMA: Detected" >> $OUTPUT_DIR/security_frameworks/summary.txt
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
    find / -xdev -type f -exec getfacl {} + > $OUTPUT_DIR/general/file_acls_getfacl.txt 2> /dev/null &
fi
if [ -x "$(command -v getfattr)" ]; then
    find / -xdev -type f -exec getfattr -d {} + > $OUTPUT_DIR/general/extended_file_attributes_getfattr.txt 2> /dev/null &
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

echo "  ${COL_ENTRY}>${RESET} Remote Access Tools"
mkdir $OUTPUT_DIR/software/remote_tools 2> /dev/null

# TeamViewer
if [ -d "/opt/teamviewer" ] || [ -d "/var/log/teamviewer" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/teamviewer 2> /dev/null
    find /opt/teamviewer -name "*.log" -o -name "*.conf" 2> /dev/null | head -50 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/teamviewer/ 2> /dev/null
    done
    cp -rp /var/log/teamviewer $OUTPUT_DIR/software/remote_tools/teamviewer/ 2> /dev/null
    find /home -maxdepth 3 -path "*/.config/teamviewer*" -type d 2> /dev/null | head -10 | while read tv_dir; do
        username=`echo "$tv_dir" | cut -d'/' -f3`
        mkdir -p $OUTPUT_DIR/software/remote_tools/teamviewer/$username 2> /dev/null
        cp -rp "$tv_dir" $OUTPUT_DIR/software/remote_tools/teamviewer/$username/ 2> /dev/null
    done
fi

# AnyDesk
find /home -maxdepth 3 -name ".anydesk" -type d 2> /dev/null | head -10 | while read anydesk_dir; do
    username=`echo "$anydesk_dir" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/remote_tools/anydesk/$username 2> /dev/null
    find "$anydesk_dir" \( -name "*.log" -o -name "*.trace" -o -name "connection_trace.txt" \) 2> /dev/null | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/anydesk/$username/ 2> /dev/null
    done
done
if [ -d "/usr/share/anydesk" ]; then
    find /usr/share/anydesk -type f -name "*.log" 2> /dev/null | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/anydesk/ 2> /dev/null
    done
fi

# RustDesk
find /home -maxdepth 4 -path "*/.config/rustdesk/*" -type f 2> /dev/null | head -50 | while read file; do
    username=`echo "$file" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/remote_tools/rustdesk/$username 2> /dev/null
    cp -p "$file" $OUTPUT_DIR/software/remote_tools/rustdesk/$username/ 2> /dev/null
done

# Chrome Remote Desktop
if [ -f "/var/log/chrome-remote-desktop.log" ] || [ -d "/opt/google/chrome-remote-desktop" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/chrome_remote_desktop 2> /dev/null
    cp /var/log/chrome-remote-desktop.log $OUTPUT_DIR/software/remote_tools/chrome_remote_desktop/ 2> /dev/null
    find /tmp -name "chrome_remote_desktop_*.log" 2> /dev/null | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/remote_tools/chrome_remote_desktop/ 2> /dev/null
    done
fi

# VNC variants (TightVNC, TigerVNC, RealVNC, UltraVNC)
vnc_found=0
find /home -maxdepth 3 \( -name ".vnc" -o -name ".tightvnc" -o -name ".tigervnc" -o -name ".ultravnc" \) -type d 2> /dev/null | head -10 | while read vnc_dir; do
    if [ $vnc_found -eq 0 ]; then
        vnc_found=1
    fi
    username=`echo "$vnc_dir" | cut -d'/' -f3`
    vnc_type=`basename "$vnc_dir"`
    mkdir -p $OUTPUT_DIR/software/remote_tools/vnc/$username/$vnc_type 2> /dev/null
    find "$vnc_dir" \( -name "*.log" -o -name "*.pid" -o -name "passwd" \) 2> /dev/null | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/vnc/$username/$vnc_type/ 2> /dev/null
    done
done
# System VNC files
if [ -d "/etc/vnc" ]; then
    cp -rp /etc/vnc $OUTPUT_DIR/software/remote_tools/vnc/ 2> /dev/null
fi
find /var/log -name "*vnc*.log" -o -name "*tigervnc*" 2> /dev/null | head -20 | while read log; do
    cp -p "$log" $OUTPUT_DIR/software/remote_tools/vnc/ 2> /dev/null
done

# Remmina
find /home -maxdepth 4 -path "*/.config/remmina/*" -o -path "*/.local/share/remmina/*" 2> /dev/null | head -50 | while read file; do
    if [ -f "$file" ]; then
        username=`echo "$file" | cut -d'/' -f3`
        mkdir -p $OUTPUT_DIR/software/remote_tools/remmina/$username 2> /dev/null
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/remmina/$username/ 2> /dev/null
    fi
done

# NoMachine
if [ -d "/usr/NX" ] || [ -d "/var/log/nxserver" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/nomachine 2> /dev/null
    find /usr/NX -name "*.log" -o -name "*.cfg" 2> /dev/null | head -50 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/nomachine/ 2> /dev/null
    done
    cp -rp /var/log/nxserver $OUTPUT_DIR/software/remote_tools/nomachine/ 2> /dev/null
fi

# Splashtop
find /var/log -name "*splashtop*" 2> /dev/null | head -10 | while read log; do
    mkdir -p $OUTPUT_DIR/software/remote_tools/splashtop 2> /dev/null
    cp -p "$log" $OUTPUT_DIR/software/remote_tools/splashtop/ 2> /dev/null
done

# X2Go
if [ -f "/var/lib/x2go/x2go_sessions" ] || [ -d "/etc/x2go" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/x2go 2> /dev/null
    cp /var/lib/x2go/x2go_sessions $OUTPUT_DIR/software/remote_tools/x2go/ 2> /dev/null
    find /var/log -name "x2go*.log" 2> /dev/null | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/remote_tools/x2go/ 2> /dev/null
    done
fi

# XRDP
if [ -d "/etc/xrdp" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/xrdp 2> /dev/null
    find /etc/xrdp -name "*.ini" -o -name "*.conf" 2> /dev/null | while read conf; do
        cp -p "$conf" $OUTPUT_DIR/software/remote_tools/xrdp/ 2> /dev/null
    done
    find /var/log -name "xrdp*.log" 2> /dev/null | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/remote_tools/xrdp/ 2> /dev/null
    done
fi

# Apache Guacamole
if [ -d "/etc/guacamole" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/guacamole 2> /dev/null
    cp -rp /etc/guacamole $OUTPUT_DIR/software/remote_tools/guacamole/ 2> /dev/null
fi

# DWService
if [ -d "/usr/share/dwagent" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/dwservice 2> /dev/null
    find /usr/share/dwagent \( -name "*.log" -o -name "*.cfg" \) 2> /dev/null | head -20 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/dwservice/ 2> /dev/null
    done
fi

# Parsec
find /home -maxdepth 4 -path "*/.parsec/*" -type f 2> /dev/null | head -20 | while read file; do
    username=`echo "$file" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/remote_tools/parsec/$username 2> /dev/null
    cp -p "$file" $OUTPUT_DIR/software/remote_tools/parsec/$username/ 2> /dev/null
done

# ConnectWise/ScreenConnect
if [ -d "/opt/screenconnect" ] || [ -d "/opt/connectwise" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/screenconnect 2> /dev/null
    find /opt/screenconnect /opt/connectwise -name "*.log" -o -name "*.config" 2> /dev/null | head -50 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/screenconnect/ 2> /dev/null
    done
fi

# LogMeIn
if [ -d "/opt/logmein" ]; then
    mkdir $OUTPUT_DIR/software/remote_tools/logmein 2> /dev/null
    find /opt/logmein \( -name "*.log" -o -name "*.conf" \) 2> /dev/null | head -20 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/remote_tools/logmein/ 2> /dev/null
    done
fi

# SSH Tunneling Scripts (potential remote access)
echo "  ${COL_ENTRY}>${RESET} SSH Tunneling Scripts"
find /home /root -maxdepth 3 \( -name "*tunnel*.sh" -o -name "*forward*.sh" -o -name "*vnc*.sh" \) 2> /dev/null | head -50 | while read script; do
    if [ -f "$script" ]; then
        mkdir -p $OUTPUT_DIR/software/remote_tools/ssh_tunnels 2> /dev/null
        cp -p "$script" $OUTPUT_DIR/software/remote_tools/ssh_tunnels/ 2> /dev/null
    fi
done

# Remote Access Related Systemd Services
echo "  ${COL_ENTRY}>${RESET} Remote Access Systemd Services"
mkdir $OUTPUT_DIR/software/remote_tools/systemd_services 2> /dev/null
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -type f 2> /dev/null | while read service; do
    grep -qiE "teamviewer|anydesk|rustdesk|vnc|rdp|nomachine|splashtop|x2go|guacamole|dwservice|parsec|connectwise|logmein" "$service" 2> /dev/null
    if [ $? -eq 0 ]; then
        cp -p "$service" $OUTPUT_DIR/software/remote_tools/systemd_services/ 2> /dev/null
    fi
done

# Desktop Entries for Remote Tools
echo "  ${COL_ENTRY}>${RESET} Remote Access Desktop Entries"
mkdir $OUTPUT_DIR/software/remote_tools/desktop_entries 2> /dev/null
find /usr/share/applications /usr/local/share/applications -name "*.desktop" 2> /dev/null | while read desktop; do
    grep -qiE "teamviewer|anydesk|rustdesk|vnc|rdp|nomachine|splashtop|x2go|remmina|guacamole|parsec" "$desktop" 2> /dev/null
    if [ $? -eq 0 ]; then
        cp -p "$desktop" $OUTPUT_DIR/software/remote_tools/desktop_entries/ 2> /dev/null
    fi
done

# Remote Access Tools Summary
echo "  ${COL_ENTRY}>${RESET} Remote Access Tools Summary"
find $OUTPUT_DIR/software/remote_tools -type f 2> /dev/null | wc -l > $OUTPUT_DIR/software/remote_tools_artifact_count.txt
ls -1 $OUTPUT_DIR/software/remote_tools 2> /dev/null | grep -v "artifact_count" > $OUTPUT_DIR/software/remote_tools_detected.txt

echo "  ${COL_ENTRY}>${RESET} Application-Specific Artifacts"
mkdir $OUTPUT_DIR/software/applications 2> /dev/null

# Confluence
find /opt /var /usr/local -path "*/confluence/*" -type d 2> /dev/null | head -5 | while read conf_dir; do
    mkdir -p $OUTPUT_DIR/software/applications/confluence 2> /dev/null
    find "$conf_dir" -name "confluence.cfg.xml" -o -name "atlassian-confluence.log" -o -name "catalina.out" 2> /dev/null | head -50 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/applications/confluence/ 2> /dev/null
    done
    # Get version info
    find "$conf_dir" -name "confluence-build.properties" -o -name "confluence.version" 2> /dev/null | head -5 | while read version_file; do
        cp -p "$version_file" $OUTPUT_DIR/software/applications/confluence/ 2> /dev/null
    done
done

# Jira
find /opt /var /usr/local -path "*/jira/*" -type d 2> /dev/null | head -5 | while read jira_dir; do
    mkdir -p $OUTPUT_DIR/software/applications/jira 2> /dev/null
    find "$jira_dir" -name "jira-config.properties" -o -name "dbconfig.xml" -o -name "atlassian-jira.log" 2> /dev/null | head -50 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/applications/jira/ 2> /dev/null
    done
done

# Bitbucket
find /opt /var /usr/local -path "*/bitbucket/*" -type d 2> /dev/null | head -5 | while read bb_dir; do
    mkdir -p $OUTPUT_DIR/software/applications/bitbucket 2> /dev/null
    find "$bb_dir" -name "bitbucket.properties" -o -name "bitbucket-config.properties" -o -name "atlassian-bitbucket.log" 2> /dev/null | head -50 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/applications/bitbucket/ 2> /dev/null
    done
done

# Tomcat
find /opt /var /usr/local -name "tomcat*" -type d 2> /dev/null | head -10 | while read tomcat_dir; do
    if [ -d "$tomcat_dir/logs" ] || [ -d "$tomcat_dir/conf" ]; then
        mkdir -p $OUTPUT_DIR/software/applications/tomcat 2> /dev/null
        # Logs
        find "$tomcat_dir/logs" -name "*.log" -o -name "*.txt" -o -name "*.out" 2> /dev/null | head -100 | while read log; do
            cp -p "$log" $OUTPUT_DIR/software/applications/tomcat/ 2> /dev/null
        done
        # Configuration
        find "$tomcat_dir/conf" -name "*.xml" -o -name "*.properties" 2> /dev/null | head -20 | while read conf; do
            cp -p "$conf" $OUTPUT_DIR/software/applications/tomcat/ 2> /dev/null
        done
        # Version info
        find "$tomcat_dir" -name "RELEASE-NOTES" -o -name "VERSION" 2> /dev/null | head -5 | while read version; do
            cp -p "$version" $OUTPUT_DIR/software/applications/tomcat/ 2> /dev/null
        done
    fi
done

# JBoss/WildFly
find /opt /var /usr/local -name "jboss*" -o -name "wildfly*" -type d 2> /dev/null | head -5 | while read jboss_dir; do
    if [ -d "$jboss_dir/standalone" ] || [ -d "$jboss_dir/domain" ]; then
        mkdir -p $OUTPUT_DIR/software/applications/jboss 2> /dev/null
        # Logs
        find "$jboss_dir" -path "*/log/*.log" 2> /dev/null | head -50 | while read log; do
            cp -p "$log" $OUTPUT_DIR/software/applications/jboss/ 2> /dev/null
        done
        # Configuration
        find "$jboss_dir" -name "standalone.xml" -o -name "domain.xml" -o -name "host.xml" 2> /dev/null | head -10 | while read conf; do
            cp -p "$conf" $OUTPUT_DIR/software/applications/jboss/ 2> /dev/null
        done
    fi
done

# WebLogic
find /opt /var /usr/local -path "*/weblogic/*" -type d 2> /dev/null | head -5 | while read wl_dir; do
    mkdir -p $OUTPUT_DIR/software/applications/weblogic 2> /dev/null
    find "$wl_dir" -name "*.log" -o -name "config.xml" -o -name "weblogic.xml" 2> /dev/null | head -50 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/applications/weblogic/ 2> /dev/null
    done
done

# WebSphere
find /opt /var /usr/local -path "*/WebSphere/*" -type d 2> /dev/null | head -5 | while read ws_dir; do
    mkdir -p $OUTPUT_DIR/software/applications/websphere 2> /dev/null
    find "$ws_dir" -name "*.log" -o -name "server.xml" -o -name "security.xml" 2> /dev/null | head -50 | while read file; do
        cp -p "$file" $OUTPUT_DIR/software/applications/websphere/ 2> /dev/null
    done
done

# Apache Struts (often within other apps)
find /opt /var /usr/local -name "struts.xml" -o -name "struts-*.jar" -o -name "struts2-*.jar" 2> /dev/null | head -50 | while read struts_file; do
    mkdir -p $OUTPUT_DIR/software/applications/struts 2> /dev/null
    cp -p "$struts_file" $OUTPUT_DIR/software/applications/struts/ 2> /dev/null
done

# Jenkins
find /var/lib /opt /usr/local -name "jenkins*" -type d 2> /dev/null | head -5 | while read jenkins_dir; do
    if [ -f "$jenkins_dir/config.xml" ] || [ -d "$jenkins_dir/jobs" ]; then
        mkdir -p $OUTPUT_DIR/software/applications/jenkins 2> /dev/null
        # Main config
        cp -p "$jenkins_dir/config.xml" $OUTPUT_DIR/software/applications/jenkins/ 2> /dev/null
        cp -p "$jenkins_dir/credentials.xml" $OUTPUT_DIR/software/applications/jenkins/ 2> /dev/null
        # Version info
        cp -p "$jenkins_dir/.jenkins.version" $OUTPUT_DIR/software/applications/jenkins/ 2> /dev/null
        # Recent logs
        find "$jenkins_dir" -name "*.log" -mtime -7 2> /dev/null | head -50 | while read log; do
            cp -p "$log" $OUTPUT_DIR/software/applications/jenkins/ 2> /dev/null
        done
    fi
done

# GitLab
if [ -d "/opt/gitlab" ] || [ -d "/var/opt/gitlab" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/gitlab 2> /dev/null
    # Config files
    cp /etc/gitlab/gitlab.rb $OUTPUT_DIR/software/applications/gitlab/ 2> /dev/null
    # Logs
    find /var/log/gitlab -name "*.log" -mtime -7 2> /dev/null | head -50 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/gitlab/ 2> /dev/null
    done
fi

# Elasticsearch
if [ -d "/etc/elasticsearch" ] || [ -d "/var/log/elasticsearch" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/elasticsearch 2> /dev/null
    cp -p /etc/elasticsearch/*.yml $OUTPUT_DIR/software/applications/elasticsearch/ 2> /dev/null
    find /var/log/elasticsearch -name "*.log" -mtime -7 2> /dev/null | head -50 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/elasticsearch/ 2> /dev/null
    done
fi

# Kibana
if [ -d "/etc/kibana" ] || [ -d "/var/log/kibana" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/kibana 2> /dev/null
    cp -p /etc/kibana/*.yml $OUTPUT_DIR/software/applications/kibana/ 2> /dev/null
    find /var/log/kibana -name "*.log" -mtime -7 2> /dev/null | head -50 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/kibana/ 2> /dev/null
    done
fi

# Logstash
if [ -d "/etc/logstash" ] || [ -d "/var/log/logstash" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/logstash 2> /dev/null
    cp -p /etc/logstash/*.yml $OUTPUT_DIR/software/applications/logstash/ 2> /dev/null
    find /etc/logstash/conf.d -name "*.conf" 2> /dev/null | while read conf; do
        cp -p "$conf" $OUTPUT_DIR/software/applications/logstash/ 2> /dev/null
    done
fi

# Grafana
if [ -d "/etc/grafana" ] || [ -d "/var/lib/grafana" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/grafana 2> /dev/null
    cp -p /etc/grafana/*.ini $OUTPUT_DIR/software/applications/grafana/ 2> /dev/null
    find /var/log/grafana -name "*.log" -mtime -7 2> /dev/null | head -20 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/grafana/ 2> /dev/null
    done
fi

# Nagios
if [ -d "/etc/nagios" ] || [ -d "/usr/local/nagios" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/nagios 2> /dev/null
    find /etc/nagios /usr/local/nagios/etc -name "*.cfg" 2> /dev/null | head -50 | while read cfg; do
        cp -p "$cfg" $OUTPUT_DIR/software/applications/nagios/ 2> /dev/null
    done
    find /var/log/nagios /usr/local/nagios/var -name "*.log" -mtime -7 2> /dev/null | head -20 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/nagios/ 2> /dev/null
    done
fi

# Splunk Universal Forwarder
if [ -d "/opt/splunkforwarder" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/splunk_forwarder 2> /dev/null
    cp -p /opt/splunkforwarder/etc/system/local/*.conf $OUTPUT_DIR/software/applications/splunk_forwarder/ 2> /dev/null
    find /opt/splunkforwarder/var/log/splunk -name "*.log" -mtime -7 2> /dev/null | head -20 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/splunk_forwarder/ 2> /dev/null
    done
fi

# WordPress
find /var/www /opt /usr/local -name "wp-config.php" 2> /dev/null | head -20 | while read wp_conf; do
    mkdir -p $OUTPUT_DIR/software/applications/wordpress 2> /dev/null
    cp -p "$wp_conf" $OUTPUT_DIR/software/applications/wordpress/ 2> /dev/null
    wp_dir=`dirname "$wp_conf"`
    # Get version
    if [ -f "$wp_dir/wp-includes/version.php" ]; then
        cp -p "$wp_dir/wp-includes/version.php" $OUTPUT_DIR/software/applications/wordpress/ 2> /dev/null
    fi
    # Get installed plugins list
    if [ -d "$wp_dir/wp-content/plugins" ]; then
        ls -la "$wp_dir/wp-content/plugins" > $OUTPUT_DIR/software/applications/wordpress/installed_plugins.txt 2> /dev/null
    fi
done

# Drupal
find /var/www /opt /usr/local -name "settings.php" -path "*/sites/*/settings.php" 2> /dev/null | head -20 | while read drupal_conf; do
    mkdir -p $OUTPUT_DIR/software/applications/drupal 2> /dev/null
    cp -p "$drupal_conf" $OUTPUT_DIR/software/applications/drupal/ 2> /dev/null
done

# Joomla
find /var/www /opt /usr/local -name "configuration.php" -path "*/joomla*/configuration.php" 2> /dev/null | head -20 | while read joomla_conf; do
    mkdir -p $OUTPUT_DIR/software/applications/joomla 2> /dev/null
    cp -p "$joomla_conf" $OUTPUT_DIR/software/applications/joomla/ 2> /dev/null
done

# phpMyAdmin
find /var/www /opt /usr/local /usr/share -name "config.inc.php" -path "*phpmyadmin*" 2> /dev/null | head -10 | while read pma_conf; do
    mkdir -p $OUTPUT_DIR/software/applications/phpmyadmin 2> /dev/null
    cp -p "$pma_conf" $OUTPUT_DIR/software/applications/phpmyadmin/ 2> /dev/null
done

# Redis
if [ -f "/etc/redis/redis.conf" ] || [ -f "/etc/redis.conf" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/redis 2> /dev/null
    cp -p /etc/redis/redis.conf /etc/redis.conf $OUTPUT_DIR/software/applications/redis/ 2> /dev/null
    find /var/log -name "redis*.log" -mtime -7 2> /dev/null | head -10 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/redis/ 2> /dev/null
    done
fi

# MongoDB
if [ -d "/etc/mongod.conf" ] || [ -f "/etc/mongodb.conf" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/mongodb 2> /dev/null
    cp -p /etc/mongod.conf /etc/mongodb.conf $OUTPUT_DIR/software/applications/mongodb/ 2> /dev/null
    find /var/log -name "mongo*.log" -mtime -7 2> /dev/null | head -10 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/mongodb/ 2> /dev/null
    done
fi

# Apache Solr
find /opt /var /usr/local -name "solr" -type d 2> /dev/null | head -5 | while read solr_dir; do
    if [ -f "$solr_dir/bin/solr" ] || [ -d "$solr_dir/server" ]; then
        mkdir -p $OUTPUT_DIR/software/applications/solr 2> /dev/null
        find "$solr_dir" -name "solr.xml" -o -name "solrconfig.xml" 2> /dev/null | head -20 | while read conf; do
            cp -p "$conf" $OUTPUT_DIR/software/applications/solr/ 2> /dev/null
        done
        find "$solr_dir" -name "*.log" -mtime -7 2> /dev/null | head -20 | while read log; do
            cp -p "$log" $OUTPUT_DIR/software/applications/solr/ 2> /dev/null
        done
    fi
done

# RabbitMQ
if [ -d "/etc/rabbitmq" ]; then
    mkdir -p $OUTPUT_DIR/software/applications/rabbitmq 2> /dev/null
    cp -p /etc/rabbitmq/*.conf $OUTPUT_DIR/software/applications/rabbitmq/ 2> /dev/null
    find /var/log/rabbitmq -name "*.log" -mtime -7 2> /dev/null | head -20 | while read log; do
        cp -p "$log" $OUTPUT_DIR/software/applications/rabbitmq/ 2> /dev/null
    done
fi

# ActiveMQ
find /opt /var /usr/local -name "activemq" -type d 2> /dev/null | head -5 | while read amq_dir; do
    if [ -d "$amq_dir/conf" ]; then
        mkdir -p $OUTPUT_DIR/software/applications/activemq 2> /dev/null
        cp -p "$amq_dir/conf/"*.xml $OUTPUT_DIR/software/applications/activemq/ 2> /dev/null
        find "$amq_dir/data" -name "*.log" -mtime -7 2> /dev/null | head -20 | while read log; do
            cp -p "$log" $OUTPUT_DIR/software/applications/activemq/ 2> /dev/null
        done
    fi
done

# Spring Boot Applications (by checking for application.properties/yml)
find /opt /var /usr/local -name "application.properties" -o -name "application.yml" -o -name "application.yaml" 2> /dev/null | head -50 | while read spring_conf; do
    app_dir=`dirname "$spring_conf"`
    mkdir -p $OUTPUT_DIR/software/applications/spring_boot 2> /dev/null
    cp -p "$spring_conf" $OUTPUT_DIR/software/applications/spring_boot/ 2> /dev/null
    find "$app_dir" -name "bootstrap.properties" -o -name "bootstrap.yml" 2> /dev/null | while read boot_conf; do
        cp -p "$boot_conf" $OUTPUT_DIR/software/applications/spring_boot/ 2> /dev/null
    done
done

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
    grep -A 1 displayName /Library/Receipts/InstallHistory.plist 2> /dev/null| grep string | sed 's/<string>\(.*\)<\/string>.*/\1/g'  | sed 's/^[      ]*//g'|tr  -d -c 'a-zA-Z0-9\n _-'|sort|uniq > $OUTPUT_DIR/software/osx-patchlist.txt 2> /dev/null
    ls -1 /Library/Receipts/boms /private/var/db/receipts 2> /dev/null | grep '\.bom$' > $OUTPUT_DIR/software/osx-bomlist.txt 2> /dev/null
    emerge -pev world 1> $OUTPUT_DIR/software/software-emerge.txt 2> /dev/null
    pkg_info > $OUTPUT_DIR/software/freebsd-patchlist.txt 2> /dev/null
    chkconfig --list > $OUTPUT_DIR/software/chkconfig--list.txt 2> /dev/null
    pkg info > $OUTPUT_DIR/software/freebsd-patchlist_pkg_info.txt 2> /dev/null
    
    # Package verification for Linux
    echo "  ${COL_ENTRY}>${RESET} Verifying package integrity"
    mkdir $OUTPUT_DIR/software/verification 2> /dev/null
    
    # RPM-based verification
    if [ -x /usr/bin/rpm -o -x /bin/rpm ]; then
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
        pkg check -sa 1> $OUTPUT_DIR/software/verification/pkg-check-all.txt 2> /dev/null
        pkg check -d 1> $OUTPUT_DIR/software/verification/pkg-check-dependencies.txt 2> /dev/null
        pkg check -s 1> $OUTPUT_DIR/software/verification/pkg-check-checksums.txt 2> /dev/null
    fi
    
    # OpenBSD package verification
    if [ -x /usr/sbin/pkg_check ]; then
        pkg_check 1> $OUTPUT_DIR/software/verification/pkg_check.txt 2> /dev/null
        pkg_check -F 1> $OUTPUT_DIR/software/verification/pkg_check-files.txt 2> /dev/null
    fi
    
    # Snap package verification
    if [ -x /usr/bin/snap ]; then
        snap list 1> $OUTPUT_DIR/software/verification/snap-list.txt 2> /dev/null
        snap changes 1> $OUTPUT_DIR/software/verification/snap-changes.txt 2> /dev/null
    fi
    
    # Flatpak verification
    if [ -x /usr/bin/flatpak ]; then
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
        dnf history 1> $OUTPUT_DIR/software/patches/dnf-history.txt 2> /dev/null
        dnf history list all 1> $OUTPUT_DIR/software/patches/dnf-history-all.txt 2> /dev/null
        # List available updates
        dnf check-update 1> $OUTPUT_DIR/software/patches/dnf-available-updates.txt 2> /dev/null
        # Security updates
        dnf updateinfo list security 1> $OUTPUT_DIR/software/patches/dnf-security-updates.txt 2> /dev/null
    fi
    
    # Zypper (SUSE, openSUSE)
    if [ -x /usr/bin/zypper ]; then
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
        if [ -f /var/log/emerge.log ]; then
            tail -1000 /var/log/emerge.log 1> $OUTPUT_DIR/software/patches/emerge-recent.log 2> /dev/null
        fi
        # Security patches
        glsa-check -l 1> $OUTPUT_DIR/software/patches/glsa-security-patches.txt 2> /dev/null
    fi
    
    # Pacman (Arch Linux)
    if [ -x /usr/bin/pacman ]; then
        if [ -f /var/log/pacman.log ]; then
            cp /var/log/pacman.log $OUTPUT_DIR/software/patches/ 2> /dev/null
        fi
        # List outdated packages
        pacman -Qu 1> $OUTPUT_DIR/software/patches/pacman-outdated.txt 2> /dev/null
    fi
    
    # FreeBSD
    if [ -x /usr/sbin/freebsd-update ]; then
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

echo "  ${COL_ENTRY}>${RESET} Web Browser Artifacts"
mkdir $OUTPUT_DIR/software/browsers 2> /dev/null

# Google Chrome / Chromium
chrome_found=0
# Check for Chrome in user directories
find /home -maxdepth 4 \( -path "*/.config/google-chrome/*" -o -path "*/.config/chromium/*" \) -type f 2> /dev/null | while read chrome_file; do
    if [ $chrome_found -eq 0 ]; then
        echo "      > Chrome/Chromium detected"
        chrome_found=1
    fi
    username=`echo "$chrome_file" | cut -d'/' -f3`
    browser_type=`echo "$chrome_file" | grep -o -E "google-chrome|chromium"`
    
    # Create directory structure
    mkdir -p $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type 2> /dev/null
    
    # History files
    if echo "$chrome_file" | grep -q "History"; then
        cp -p "$chrome_file" $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/ 2> /dev/null
    fi
    
    # Bookmarks
    if echo "$chrome_file" | grep -q "Bookmarks"; then
        cp -p "$chrome_file" $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/ 2> /dev/null
    fi
    
    # Preferences (contains settings)
    if echo "$chrome_file" | grep -q "Preferences"; then
        cp -p "$chrome_file" $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/ 2> /dev/null
    fi
    
    # Login Data (saved passwords)
    if echo "$chrome_file" | grep -q "Login Data"; then
        cp -p "$chrome_file" $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/ 2> /dev/null
    fi
    
    # Cookies
    if echo "$chrome_file" | grep -q "Cookies"; then
        cp -p "$chrome_file" $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/ 2> /dev/null
    fi
    
    # Web Data (autofill)
    if echo "$chrome_file" | grep -q "Web Data"; then
        cp -p "$chrome_file" $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/ 2> /dev/null
    fi
    
    # Extensions
    if echo "$chrome_file" | grep -q "/Extensions/"; then
        extension_dir=`dirname "$chrome_file"`
        extension_id=`basename "$extension_dir"`
        mkdir -p $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/extensions 2> /dev/null
        # Only copy manifest.json to identify extensions
        if [ -f "$extension_dir/manifest.json" ]; then
            mkdir -p $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/extensions/$extension_id 2> /dev/null
            cp -p "$extension_dir/manifest.json" $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/extensions/$extension_id/ 2> /dev/null
        fi
    fi
done

# Get Chrome/Chromium versions
find /home -maxdepth 5 -path "*/.config/google-chrome/*/version" -o -path "*/.config/chromium/*/version" 2> /dev/null | while read version_file; do
    username=`echo "$version_file" | cut -d'/' -f3`
    browser_type=`echo "$version_file" | grep -o -E "google-chrome|chromium"`
    cp -p "$version_file" $OUTPUT_DIR/software/browsers/chrome/$username/$browser_type/ 2> /dev/null
done

# List Chrome profiles
find /home -maxdepth 4 -type d \( -path "*/.config/google-chrome/Profile*" -o -path "*/.config/google-chrome/Default" -o -path "*/.config/chromium/Profile*" -o -path "*/.config/chromium/Default" \) 2> /dev/null | while read profile_dir; do
    username=`echo "$profile_dir" | cut -d'/' -f3`
    browser_type=`echo "$profile_dir" | grep -o -E "google-chrome|chromium"`
    profile_name=`basename "$profile_dir"`
    echo "$profile_name" >> $OUTPUT_DIR/software/browsers/chrome/$username/${browser_type}_profiles.txt 2> /dev/null
done

# Mozilla Firefox
firefox_found=0
find /home -maxdepth 3 -name ".mozilla" -type d 2> /dev/null | while read mozilla_dir; do
    if [ $firefox_found -eq 0 ]; then
        echo "      > Firefox detected"
        firefox_found=1
    fi
    username=`echo "$mozilla_dir" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/browsers/firefox/$username 2> /dev/null
    
    # Find Firefox profiles
    find "$mozilla_dir/firefox" -name "*.default*" -o -name "*.default-release*" -type d 2> /dev/null | while read profile_dir; do
        profile_name=`basename "$profile_dir"`
        mkdir -p $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name 2> /dev/null
        
        # Places.sqlite (history and bookmarks)
        cp -p "$profile_dir/places.sqlite" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        cp -p "$profile_dir/places.sqlite-wal" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        
        # Form history
        cp -p "$profile_dir/formhistory.sqlite" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        
        # Downloads
        cp -p "$profile_dir/downloads.sqlite" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        
        # Cookies
        cp -p "$profile_dir/cookies.sqlite" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        
        # Logins (encrypted passwords)
        cp -p "$profile_dir/logins.json" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        cp -p "$profile_dir/key*.db" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        
        # Preferences
        cp -p "$profile_dir/prefs.js" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        cp -p "$profile_dir/user.js" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        
        # Extensions
        cp -p "$profile_dir/extensions.json" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        cp -p "$profile_dir/addons.json" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        
        # Session data
        cp -p "$profile_dir/sessionstore.jsonlz4" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
        cp -p "$profile_dir/sessionstore-backups/recovery.jsonlz4" $OUTPUT_DIR/software/browsers/firefox/$username/$profile_name/ 2> /dev/null
    done
    
    # Firefox profiles.ini
    cp -p "$mozilla_dir/firefox/profiles.ini" $OUTPUT_DIR/software/browsers/firefox/$username/ 2> /dev/null
done

# Microsoft Edge (Chromium-based)
edge_found=0
find /home -maxdepth 4 -path "*/.config/microsoft-edge/*" -type f 2> /dev/null | while read edge_file; do
    if [ $edge_found -eq 0 ]; then
        echo "      > Microsoft Edge detected"
        edge_found=1
    fi
    username=`echo "$edge_file" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/browsers/edge/$username 2> /dev/null
    
    # Similar to Chrome structure
    if echo "$edge_file" | grep -E "History|Bookmarks|Preferences|Login Data|Cookies|Web Data"; then
        cp -p "$edge_file" $OUTPUT_DIR/software/browsers/edge/$username/ 2> /dev/null
    fi
done

# Safari (macOS)
if [ -d "/Users" ]; then  # macOS detection
    find /Users -maxdepth 3 -path "*/Library/Safari/*" -type f 2> /dev/null | while read safari_file; do
        echo "      > Safari detected"
        username=`echo "$safari_file" | cut -d'/' -f3`
        mkdir -p $OUTPUT_DIR/software/browsers/safari/$username 2> /dev/null
        
        # History
        if echo "$safari_file" | grep -q "History.db"; then
            cp -p "$safari_file" $OUTPUT_DIR/software/browsers/safari/$username/ 2> /dev/null
        fi
        
        # Bookmarks
        if echo "$safari_file" | grep -q "Bookmarks.plist"; then
            cp -p "$safari_file" $OUTPUT_DIR/software/browsers/safari/$username/ 2> /dev/null
        fi
        
        # Downloads
        if echo "$safari_file" | grep -q "Downloads.plist"; then
            cp -p "$safari_file" $OUTPUT_DIR/software/browsers/safari/$username/ 2> /dev/null
        fi
        
        # Extensions
        if echo "$safari_file" | grep -q "Extensions.plist"; then
            cp -p "$safari_file" $OUTPUT_DIR/software/browsers/safari/$username/ 2> /dev/null
        fi
    done
fi

# Opera
opera_found=0
find /home -maxdepth 4 \( -path "*/.config/opera/*" -o -path "*/.opera/*" \) -type f 2> /dev/null | while read opera_file; do
    if [ $opera_found -eq 0 ]; then
        echo "      > Opera detected"
        opera_found=1
    fi
    username=`echo "$opera_file" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/browsers/opera/$username 2> /dev/null
    
    # Opera uses similar structure to Chrome
    if echo "$opera_file" | grep -E "History|Bookmarks|Preferences|Login Data|Cookies|Web Data"; then
        cp -p "$opera_file" $OUTPUT_DIR/software/browsers/opera/$username/ 2> /dev/null
    fi
done

# Brave Browser
brave_found=0
find /home -maxdepth 4 -path "*/.config/BraveSoftware/Brave-Browser/*" -type f 2> /dev/null | while read brave_file; do
    if [ $brave_found -eq 0 ]; then
        echo "      > Brave Browser detected"
        brave_found=1
    fi
    username=`echo "$brave_file" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/browsers/brave/$username 2> /dev/null
    
    # Brave uses Chrome structure
    if echo "$brave_file" | grep -E "History|Bookmarks|Preferences|Login Data|Cookies|Web Data"; then
        cp -p "$brave_file" $OUTPUT_DIR/software/browsers/brave/$username/ 2> /dev/null
    fi
done

# Vivaldi
vivaldi_found=0
find /home -maxdepth 4 -path "*/.config/vivaldi/*" -type f 2> /dev/null | while read vivaldi_file; do
    if [ $vivaldi_found -eq 0 ]; then
        echo "      > Vivaldi detected"
        vivaldi_found=1
    fi
    username=`echo "$vivaldi_file" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/browsers/vivaldi/$username 2> /dev/null
    
    # Vivaldi uses Chrome structure
    if echo "$vivaldi_file" | grep -E "History|Bookmarks|Preferences|Login Data|Cookies|Web Data|Notes"; then
        cp -p "$vivaldi_file" $OUTPUT_DIR/software/browsers/vivaldi/$username/ 2> /dev/null
    fi
done

# Tor Browser
tor_found=0
find /home -maxdepth 4 -path "*/tor-browser*/*" -name "*.sqlite" -o -path "*/\.tor-browser*/*" -name "*.sqlite" 2> /dev/null | while read tor_file; do
    if [ $tor_found -eq 0 ]; then
        echo "      > Tor Browser detected"
        tor_found=1
    fi
    username=`echo "$tor_file" | cut -d'/' -f3`
    mkdir -p $OUTPUT_DIR/software/browsers/tor/$username 2> /dev/null
    
    # Tor Browser has Firefox structure but we want minimal collection for privacy
    cp -p "$tor_file" $OUTPUT_DIR/software/browsers/tor/$username/ 2> /dev/null
done

# Browser Cache Locations
mkdir $OUTPUT_DIR/software/browsers/cache_info 2> /dev/null

# Chrome cache
find /home -maxdepth 5 -path "*/.cache/google-chrome/*/Cache" -o -path "*/.cache/chromium/*/Cache" 2> /dev/null | while read cache_dir; do
    username=`echo "$cache_dir" | cut -d'/' -f3`
    browser=`echo "$cache_dir" | grep -o -E "google-chrome|chromium"`
    # Just get cache size info, not actual cache files
    du -sh "$cache_dir" 2> /dev/null >> $OUTPUT_DIR/software/browsers/cache_info/${username}_${browser}_cache_size.txt
done

# Firefox cache
find /home -maxdepth 5 -path "*/.cache/mozilla/firefox/*/cache2" 2> /dev/null | while read cache_dir; do
    username=`echo "$cache_dir" | cut -d'/' -f3`
    du -sh "$cache_dir" 2> /dev/null >> $OUTPUT_DIR/software/browsers/cache_info/${username}_firefox_cache_size.txt
done

# Browser Process Information (if running)
ps aux | grep -E "chrome|firefox|safari|opera|brave|vivaldi|edge" | grep -v grep > $OUTPUT_DIR/software/browsers/running_browsers.txt 2> /dev/null

# Default Browser Settings
mkdir $OUTPUT_DIR/software/browsers/system_defaults 2> /dev/null

# XDG mime settings
find /home -maxdepth 3 -name "mimeapps.list" 2> /dev/null | while read mime_file; do
    username=`echo "$mime_file" | cut -d'/' -f3`
    grep -E "text/html|x-scheme-handler/http|x-scheme-handler/https" "$mime_file" > $OUTPUT_DIR/software/browsers/system_defaults/${username}_default_browser.txt 2> /dev/null
done

# Alternatives system
update-alternatives --display x-www-browser > $OUTPUT_DIR/software/browsers/system_defaults/system_default_browser.txt 2> /dev/null

find /home -maxdepth 4 \( -path "*/.config/*/History" -o -path "*/.mozilla/firefox/*/places.sqlite" \) -mtime -7 2> /dev/null | head -50 > $OUTPUT_DIR/software/browsers/recently_used_browsers.txt

# Chrome-based extensions
find /home -maxdepth 7 -path "*/Extensions/*/manifest.json" 2> /dev/null | while read manifest; do
    username=`echo "$manifest" | cut -d'/' -f3`
    browser=`echo "$manifest" | grep -o -E "google-chrome|chromium|microsoft-edge|opera|brave|vivaldi" | head -1`
    if [ -n "$browser" ]; then
        grep -E '"name"|"version"|"description"' "$manifest" 2> /dev/null | head -3 >> $OUTPUT_DIR/software/browsers/${username}_${browser}_extensions.txt
        echo "---" >> $OUTPUT_DIR/software/browsers/${username}_${browser}_extensions.txt
    fi
done

# Firefox extensions
find /home -maxdepth 5 -name "extensions.json" -path "*/.mozilla/firefox/*" 2> /dev/null | while read ext_file; do
    username=`echo "$ext_file" | cut -d'/' -f3`
    # Extract extension names (simplified - full JSON parsing would need jq)
    grep -o '"name":"[^"]*"' "$ext_file" 2> /dev/null | cut -d'"' -f4 > $OUTPUT_DIR/software/browsers/${username}_firefox_extensions.txt
done

# Browser Security Settings
mkdir $OUTPUT_DIR/software/browsers/security_settings 2> /dev/null
find /home -maxdepth 5 \( -name "Preferences" -o -name "prefs.js" \) -path "*/.*/*" 2> /dev/null | while read pref_file; do
    username=`echo "$pref_file" | cut -d'/' -f3`
    browser_hint=`echo "$pref_file" | grep -o -E "chrome|chromium|firefox|opera|brave|vivaldi|edge" | head -1`
    grep -i "proxy" "$pref_file" 2> /dev/null > $OUTPUT_DIR/software/browsers/security_settings/${username}_${browser_hint}_proxy.txt
done

# Browser Downloads
mkdir $OUTPUT_DIR/software/browsers/downloads 2> /dev/null
# System Downloads folder
find /home -maxdepth 3 -name "Downloads" -type d 2> /dev/null | while read dl_dir; do
    username=`echo "$dl_dir" | cut -d'/' -f3`
    # Just list recent downloads, not copy them
    find "$dl_dir" -type f -mtime -30 2> /dev/null | head -100 > $OUTPUT_DIR/software/browsers/downloads/${username}_recent_downloads.txt
done

find $OUTPUT_DIR/software/browsers -type f 2> /dev/null | wc -l > $OUTPUT_DIR/software/browsers_artifact_count.txt
ls -1 $OUTPUT_DIR/software/browsers 2> /dev/null | grep -v -E "cache_info|system_defaults|security_settings|downloads|txt$" > $OUTPUT_DIR/software/browsers_detected.txt

# Create summary of all browser profiles found
echo "Browser profiles found:" > $OUTPUT_DIR/software/browser_profiles_summary.txt
find $OUTPUT_DIR/software/browsers -name "*_profiles.txt" 2> /dev/null | while read profile_list; do
    echo "  $profile_list:" >> $OUTPUT_DIR/software/browser_profiles_summary.txt
    cat "$profile_list" | sed 's/^/    /' >> $OUTPUT_DIR/software/browser_profiles_summary.txt
done


echo "  ${COL_ENTRY}>${RESET} Compiler and development tools detection"
mkdir $OUTPUT_DIR/software/development_tools 2> /dev/null

# First, check common locations and PATH for known compilers/interpreters
echo "=== Development Tools Found in PATH ===" > $OUTPUT_DIR/software/development_tools/tools_in_path.txt

# List of common development tools to check
DEV_TOOLS="gcc g++ cc c++ clang clang++ icc icpc pgcc xlc xlC javac java python python2 python3 perl perl5 ruby irb php node nodejs npm go gccgo rustc cargo swift swiftc kotlin kotlinc scala scalac ghc ocaml fpc gfortran f77 f90 f95 nasm yasm tclsh wish lua R julia dart mono mcs dotnet make gmake cmake qmake automake ant maven gradle rake pip pip3 gem npm yarn composer"

for tool in $DEV_TOOLS
do
    if command -v $tool > /dev/null 2>&1; then
        tool_path=`command -v $tool 2> /dev/null`
        echo "" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
        echo "=== $tool ===" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
        echo "Path: $tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
        ls -la "$tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt 2> /dev/null
        
        # Get version info if possible
        echo "Version:" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
        case $tool in
            gcc|g++|clang|clang++|gfortran)
                $tool --version 2> /dev/null | head -1 >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt
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
            sha256sum "$tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt 2> /dev/null
        elif [ -x /usr/bin/sha1sum ]; then
            sha1sum "$tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt 2> /dev/null
        elif [ -x /usr/bin/shasum ]; then
            shasum -a 256 "$tool_path" >> $OUTPUT_DIR/software/development_tools/tools_in_path.txt 2> /dev/null
        fi
    fi
done


if [ $PLATFORM = "linux" -o $PLATFORM = "generic" ]; then
    # RPM-based systems
    if [ -x /usr/bin/rpm -o -x /bin/rpm ]; then
        echo "=== RPM Development Packages ===" > $OUTPUT_DIR/software/development_tools/rpm_dev_packages.txt
        rpm -qa | grep -E 'gcc|clang|java|jdk|python|perl|ruby|nodejs|golang|rust|compiler|devel|sdk' | sort >> $OUTPUT_DIR/software/development_tools/rpm_dev_packages.txt 2> /dev/null
    fi
    
    # Debian-based systems
    if [ -x /usr/bin/dpkg ]; then
        echo "=== DEB Development Packages ===" > $OUTPUT_DIR/software/development_tools/deb_dev_packages.txt
        dpkg -l | grep -E 'gcc|clang|java|jdk|python|perl|ruby|nodejs|golang|rust|compiler|dev|sdk' | grep '^ii' >> $OUTPUT_DIR/software/development_tools/deb_dev_packages.txt 2> /dev/null
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
        brew list | grep -E 'gcc|llvm|java|python|perl|ruby|node|go|rust' >> $OUTPUT_DIR/software/development_tools/brew_dev_packages.txt 2> /dev/null
    fi
elif [ $PLATFORM = "solaris" ]; then
    if [ -x /usr/bin/pkg ]; then
        echo "=== Solaris Development Packages ===" > $OUTPUT_DIR/software/development_tools/solaris_dev_packages.txt
        pkg list | grep -E 'gcc|java|jdk|python|perl|ruby|developer|compiler' >> $OUTPUT_DIR/software/development_tools/solaris_dev_packages.txt 2> /dev/null
    fi
fi

echo "=== Development Tools in Standard Locations ===" > $OUTPUT_DIR/software/development_tools/standard_locations.txt

# Common directories to check (much faster than full filesystem scan)
DEV_DIRS="/usr/bin /usr/local/bin /opt/*/bin /usr/lib/jvm/*/bin /usr/lib64/jvm/*/bin /opt/rh/*/root/usr/bin /usr/local/go/bin /usr/local/rust/bin /usr/local/node*/bin /Applications/Xcode.app/Contents/Developer/usr/bin /Developer/usr/bin"

for dir in $DEV_DIRS
do
    if [ -d "$dir" ]; then
        echo "" >> $OUTPUT_DIR/software/development_tools/standard_locations.txt
        echo "=== Directory: $dir ===" >> $OUTPUT_DIR/software/development_tools/standard_locations.txt
        ls -la $dir 2> /dev/null | grep -E 'gcc|g\+\+|clang|javac|java|python|perl|ruby|node|go|rustc|swift' >> $OUTPUT_DIR/software/development_tools/standard_locations.txt 2> /dev/null
    fi
done

echo "=== Build Tools and Environments ===" > $OUTPUT_DIR/software/development_tools/build_environments.txt

# Check for build tool configurations
for config in /etc/alternatives/java* /etc/alternatives/python* /etc/alternatives/gcc* /usr/lib/jvm/default-java /etc/java* /etc/python* /etc/perl* /etc/ruby*
do
    if [ -e "$config" ]; then
        echo "" >> $OUTPUT_DIR/software/development_tools/build_environments.txt
        echo "Config: $config" >> $OUTPUT_DIR/software/development_tools/build_environments.txt
        ls -la "$config" >> $OUTPUT_DIR/software/development_tools/build_environments.txt 2> /dev/null
    fi
done

# Check environment variables
echo "" >> $OUTPUT_DIR/software/development_tools/build_environments.txt
echo "=== Development Environment Variables ===" >> $OUTPUT_DIR/software/development_tools/build_environments.txt
env | grep -E 'JAVA_HOME|PYTHON_HOME|PERL5LIB|RUBY|GCC|GOPATH|GOROOT|CARGO_HOME|NODE_PATH|PATH' | sort >> $OUTPUT_DIR/software/development_tools/build_environments.txt 2> /dev/null

# Platform specific checks
if [ $PLATFORM = "android" ]; then
    echo "=== Android Development Tools ===" > $OUTPUT_DIR/software/development_tools/android_dev_tools.txt
    
    # Check for Android SDK/NDK
    find /opt /usr/local -name "android-sdk*" -o -name "android-ndk*" 2> /dev/null | head -20 >> $OUTPUT_DIR/software/development_tools/android_dev_tools.txt
    
    # Check dalvikvm
    if command -v dalvikvm > /dev/null 2>&1; then
        dalvikvm -version >> $OUTPUT_DIR/software/development_tools/android_dev_tools.txt 2>&1
    fi
fi
echo "=== Compilers Found in Non-Standard Locations ===" > $OUTPUT_DIR/software/development_tools/nonstandard_compilers.txt

SEARCH_DIRS="/opt /usr/local /home /root"
for search_dir in $SEARCH_DIRS
do
    if [ -d "$search_dir" ]; then
        find $search_dir -maxdepth 4 -type f \( -name 'gcc' -o -name 'g++' -o -name 'clang' -o -name 'javac' -o -name 'python' -o -name 'python[23]' -o -name 'perl' -o -name 'ruby' -o -name 'go' -o -name 'rustc' -o -name 'node' \) -executable 2> /dev/null | head -50 | while read compiler
        do
            echo "" >> $OUTPUT_DIR/software/development_tools/nonstandard_compilers.txt
            echo "Found: $compiler" >> $OUTPUT_DIR/software/development_tools/nonstandard_compilers.txt
            ls -la "$compiler" >> $OUTPUT_DIR/software/development_tools/nonstandard_compilers.txt 2> /dev/null
        done
    fi
done

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

echo "  ${COL_ENTRY}>${RESET} Systemd journal logs"
if [ -x "$(command -v journalctl)" ]; then
    journalctl --no-pager -n 10000 > $OUTPUT_DIR/logs/journal_recent.txt 2> /dev/null
    journalctl --no-pager -b > $OUTPUT_DIR/logs/journal_boot.txt 2> /dev/null
    journalctl --no-pager -p err > $OUTPUT_DIR/logs/journal_errors.txt 2> /dev/null
fi

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
    find /proc/ -type f \( -name "cmdline" -o -name "psinfo" -o -name "fib_triestat" -o -name "status" -o -name "connector" -o -name "protocols" -o -name "route" -o -name "fib_trie" -o -name "snmp*" \) 2> /dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
elif [ $PLATFORM = "aix" ]
then
    find /proc/ -type f \( -name "cred" -o -name "psinfo" -o -name "mmap" -o -name "cwd" -o -name "fd" -o -name "sysent" \) 2> /dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
elif [ $PLATFORM = "linux" ]
then
    find /proc/ -type f \( -name "cmdline" -o -name "fib_triestat" -o -name "status" -o -name "connector" -o -name "protocols" -o -name "route" -o -name "fib_trie" -o -name "snmp*" \) 2> /dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
elif [ $PLATFORM = "android" ]
then
    find /proc/ -type f \( -name 'cmdline' -o -name 'fib_triestat' -o -name 'status' -o -name 'connector' -o -name 'route' -o -name 'fib_trie' \) 2> /dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/procfiles`dirname $line`" 2> /dev/null
	done
elif [ $PLATFORM = "generic" ]
then
    find /proc/ -type f \( -name "cmdline" -o -name "fib_triestat" -o -name "status" -o -name "connector" -o -name "protocols" -o -name "route" -o -name "fib_trie" -o -name "snmp*" \) 2> /dev/null | while read line
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
	find / -size $TAR_MAX_FILESIZE -type f -iname "*.plist" 2> /dev/null | while read line
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
	find / -size $TAR_MAX_FILESIZE -type f -iname "*.apk" 2> /dev/null | while read line
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
	find / -type f -a -perm /6000 2> /dev/null | while read line
	do
		mkdir -p "$OUTPUT_DIR/setuid`dirname $line`" 2> /dev/null
		cp -p "$line" "$OUTPUT_DIR/setuid`dirname $line`" 2> /dev/null
	done
else
	echo "  ${COL_ENTRY}>${RESET} Finding all SUID/SGID binaries"
	find / -type f -a \( -perm -u+s -o -perm -g+s \) 2> /dev/null | while read line
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
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "solaris" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec digest -a sha256 -v {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec csum -h MD5 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi	
elif [ $PLATFORM = "mac" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a \( -perm -u+s -o -perm -g+s \) -exec shasum -a 256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "android" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find / -size $HASH_MAX_FILESIZE -type f -a -perm /6000 -exec shasum -a 256 {} \; 2> /dev/null | while read line
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
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "solaris" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec digest -a sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ /export/home/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec csum -h MD5 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	fi	
elif [ $PLATFORM = "mac" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find /Users/ -size $HASH_MAX_FILESIZE -type f -exec shasum -a 256 {} \; 2> /dev/null | while read line
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
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done
    fi		
elif [ $PLATFORM = "solaris" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec digest -a sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec csum -h MD5 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/shaMD5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /tmp/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi
elif [ $PLATFORM = "mac" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -size $HASH_MAX_FILESIZE -type f -exec shasum -a 256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	fi	
elif [ $PLATFORM = "android" ]
then
	echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/ /storage/ /system/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ dirs"
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec sha256sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec sha1sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec md5sum {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec openssl dgst -sha256 {} \; 2> /dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins 2> /dev/null
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find /bin/ /storage/ /system/ /sys/module/ /sbin/ /oem/ /odm/ /sdcard/ /mmt/ -size $HASH_MAX_FILESIZE -type f -exec shasum -a 256 {} \; 2> /dev/null | while read line
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
ss -tulpan > $OUTPUT_DIR/network/ss_tulpan.txt 2>/dev/null
ss -oemitu > $OUTPUT_DIR/network/ss_detailed.txt 2>/dev/null
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
    grep -l "disable.*=.*no" /etc/xinetd.d/* 2> /dev/null | while read service_file
    do
        echo "Service: `basename $service_file`" >> $OUTPUT_DIR/network/services/xinetd-enabled-services.txt
        grep -E "server|port|socket_type|protocol" $service_file >> $OUTPUT_DIR/network/services/xinetd-enabled-services.txt 2> /dev/null
        echo "" >> $OUTPUT_DIR/network/services/xinetd-enabled-services.txt
    done
fi

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
    # Android doesn't use traditional inetd/xinetd
    # List running services
    dumpsys connectivity 1> $OUTPUT_DIR/network/services/android-connectivity.txt 2> /dev/null
    # Get network service properties
    getprop | grep -E "net\.|dhcp\.|wifi\." > $OUTPUT_DIR/network/services/android-network-props.txt 2> /dev/null
    # List network-related services
    service list | grep -E "network|wifi|connectivity|netd" > $OUTPUT_DIR/network/services/android-network-services.txt 2> /dev/null
    
else    
    # SystemD socket activation (modern replacement for inetd)
    if command -v systemctl > /dev/null 2>&1; then
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
echo "=== Active Network Services ===" > $OUTPUT_DIR/network/services/active-listeners.txt

# Get listening services with process information
if command -v ss > /dev/null 2>&1; then
    ss -tlnp 2> /dev/null | grep LISTEN >> $OUTPUT_DIR/network/services/active-listeners.txt
    ss -ulnp 2> /dev/null >> $OUTPUT_DIR/network/services/active-listeners.txt
elif command -v netstat > /dev/null 2>&1; then
    netstat -tlnp 2> /dev/null | grep LISTEN >> $OUTPUT_DIR/network/services/active-listeners.txt
    netstat -ulnp 2> /dev/null >> $OUTPUT_DIR/network/services/active-listeners.txt
fi

# Check xinetd/inetd process status
echo "" >> $OUTPUT_DIR/network/services/active-listeners.txt
echo "=== Super-server Status ===" >> $OUTPUT_DIR/network/services/active-listeners.txt
ps aux | grep -E "[x]inetd|[i]netd" >> $OUTPUT_DIR/network/services/active-listeners.txt 2> /dev/null

# tcpwrappers configuration
if [ -f /etc/hosts.allow ]; then
    cp /etc/hosts.allow $OUTPUT_DIR/network/services/ 2> /dev/null
fi
if [ -f /etc/hosts.deny ]; then
    cp /etc/hosts.deny $OUTPUT_DIR/network/services/ 2> /dev/null
fi

# Create services summary
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
    SOCKET_COUNT=`grep -c "\.socket" $OUTPUT_DIR/network/services/systemd-sockets-status.txt 2> /dev/null || echo 0`
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
	
		esxcli network nic list 2> /dev/null | grep -E "^vmnic" | awk '{print $1}' | while read nic; do
			[ -n "$nic" ] && {
				esxcli network nic get -n "$nic" > "$OUTPUT_DIR/virtual/esxi/network/nics/${nic}_details.txt" 2> /dev/null
				esxcli network nic stats get -n "$nic" > "$OUTPUT_DIR/virtual/esxi/network/nics/${nic}_stats.txt" 2> /dev/null
			}
		done
		esxcli network vswitch standard list 1> $OUTPUT_DIR/virtual/esxi/network/vswitches/standard_list.txt 2> /dev/null
		esxcli network vswitch dvs vmware list 1> $OUTPUT_DIR/virtual/esxi/network/vswitches/dvs_list.txt 2> /dev/null
		esxcli network vswitch standard list 2> /dev/null | grep "^   " | awk '{print $1}' | while read vswitch; do
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

			vim-cmd hostsvc/datastore/list 2> /dev/null | grep -E "url.*\"" | sed 's/.*"\(.*\)".*/\1/' | while read ds_path; do
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
			
			vim-cmd vmsvc/getallvms 2> /dev/null | awk 'NR>1 {print $1}' | while read vmid; do
				if [ -n "$vmid" ] && [ "$vmid" -eq "$vmid" ] 2> /dev/null; then
					echo "  ${COL_ENTRY}>${RESET} Processing VM ID: $vmid"
					
					# Get VM name for directory
					VM_NAME=$(vim-cmd vmsvc/get.summary $vmid 2> /dev/null | grep -E "name = " | head -1 | sed 's/.*= "\(.*\)".*/\1/' | sed 's/[^a-zA-Z0-9._-]/_/g')
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
		VBOX_HOME=$(VBoxManage list systemproperties 2> /dev/null | grep "Default machine folder:" | sed 's/Default machine folder:[ ]*//')
		VBOX_LOG_FOLDER=$(VBoxManage list systemproperties 2> /dev/null | grep "Log folder:" | sed 's/Log folder:[ ]*//')
		VBOX_VRDP_AUTH=$(VBoxManage list systemproperties 2> /dev/null | grep "VRDE auth library:" | sed 's/VRDE auth library:[ ]*//')

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
		VBoxManage list natnets 2> /dev/null | grep "NetworkName:" | awk '{print $2}' | while read natnet; do
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
				find "$homedir/VirtualBox VMs" -name "*.vbox" -o -name "*.vbox-prev" 2> /dev/null | head -100 >> $OUTPUT_DIR/virtual/vbox/vms/vm_files.txt
			fi
		done

		if [ -n "$VBOX_HOME" ] && [ -d "$VBOX_HOME" ]; then
			echo "VirtualBox Home: $VBOX_HOME" > $OUTPUT_DIR/virtual/vbox/logs/log_locations.txt
			find "$VBOX_HOME" -name "*.log" -type f -mtime -7 2> /dev/null | head -100 >> $OUTPUT_DIR/virtual/vbox/logs/recent_logs.txt
			find "$VBOX_HOME" -name "VBox.log*" -type f 2> /dev/null | head -50 >> $OUTPUT_DIR/virtual/vbox/logs/vbox_logs.txt
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
		virsh list --all --name 2> /dev/null | while read vm; do
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
				virsh domblklist "$vm" 2> /dev/null | tail -n +3 | awk '{print $1}' | while read device; do
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
				virsh domiflist "$vm" 2> /dev/null | tail -n +3 | awk '{print $1}' | while read iface; do
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
				virsh snapshot-list "$vm" --name 2> /dev/null | while read snap; do
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
				if virsh domstate "$vm" 2> /dev/null | grep -q "running"; then
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
		virsh net-list --all --name 2> /dev/null | while read net; do
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
		virsh pool-list --all --name 2> /dev/null | while read pool; do
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
				virsh vol-list "$pool" 2> /dev/null | tail -n +3 | awk '{print $1}' | while read vol; do
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
		virsh nwfilter-list --name 2> /dev/null | while read filter; do
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
			find /var/log/libvirt -name "*.log" -type f -mtime -7 -size -100M 2> /dev/null | while read logfile; do
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
				find "$dir" \( -name "*.qcow2" -o -name "*.img" -o -name "*.raw" \) -type f 2> /dev/null | while read img; do
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
		find /etc/libvirt -name "*.conf" -type f 2> /dev/null | while read conf; do
			echo "$conf" >> $OUTPUT_DIR/virtual/libvirt_config_files.txt
			ls -la "$conf" >> $OUTPUT_DIR/virtual/libvirt_config_files.txt
		done
		
		# libvirt logs location
		if [ -d "/var/log/libvirt" ]; then
			ls -la /var/log/libvirt/ > $OUTPUT_DIR/virtual/libvirt_log_listing.txt 2> /dev/null
			# Copy recent QEMU logs (last 7 days)
			find /var/log/libvirt/qemu -name "*.log" -mtime -7 -type f 2> /dev/null | while read log; do
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
			ctr namespace ls -q 2> /dev/null | while read namespace; do
				[ -z "$namespace" ] && continue
				echo "  ${COL_ENTRY}>${RESET} Processing namespace: $namespace"
				mkdir -p $OUTPUT_DIR/containers/containerd/namespaces/$namespace
				ctr -n $namespace namespace stats 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/stats.txt 2> /dev/null
				echo "  ${COL_ENTRY}>${RESET} Collecting images in namespace $namespace"
				ctr -n $namespace images ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/images_list.txt 2> /dev/null
				ctr -n $namespace images ls -q 2> /dev/null | while read image; do
					[ -z "$image" ] && continue
					# Sanitize image name for filename
					safe_image=$(echo "$image" | sed 's/[^a-zA-Z0-9._-]/_/g')
					ctr -n $namespace images info $image 1> $OUTPUT_DIR/containers/containerd/images/${namespace}_${safe_image}_info.json 2> /dev/null
				done
				echo "  ${COL_ENTRY}>${RESET} Collecting containers in namespace $namespace"
				ctr -n $namespace containers ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/containers_list.txt 2> /dev/null
				ctr -n $namespace containers ls -q 2> /dev/null | while read container; do
					[ -z "$container" ] && continue
					mkdir -p $OUTPUT_DIR/containers/containerd/containers/$namespace
					ctr -n $namespace containers info $container 1> $OUTPUT_DIR/containers/containerd/containers/$namespace/${container}_info.json 2> /dev/null
					ctr -n $namespace containers label $container 1> $OUTPUT_DIR/containers/containerd/containers/$namespace/${container}_labels.txt 2> /dev/null
				done
				echo "  ${COL_ENTRY}>${RESET} Collecting tasks in namespace $namespace"
				ctr -n $namespace tasks ls 1> $OUTPUT_DIR/containers/containerd/namespaces/$namespace/tasks_list.txt 2> /dev/null
				ctr -n $namespace tasks ls -q 2> /dev/null | while read task; do
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
			timeout 5s ctr events 2> /dev/null | head -n 100 > $OUTPUT_DIR/containers/containerd/events/recent_events.txt 2> /dev/null
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
			find /var/lib/containerd -type d 2> /dev/null | head -1000 > $OUTPUT_DIR/containers/containerd/state_directory_structure.txt
			du -sh /var/lib/containerd/* 2> /dev/null > $OUTPUT_DIR/containers/containerd/state_directory_sizes.txt
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
			mkdir -p $OUTPUT_DIR/containers/docker 2> /dev/null
			mkdir -p $OUTPUT_DIR/containers/docker/config 2> /dev/null
			mkdir -p $OUTPUT_DIR/containers/docker/runtime 2> /dev/null
			mkdir -p $OUTPUT_DIR/containers/docker/images 2> /dev/null
			mkdir -p $OUTPUT_DIR/containers/docker/containers 2> /dev/null
			mkdir -p $OUTPUT_DIR/containers/docker/networks 2> /dev/null
			mkdir -p $OUTPUT_DIR/containers/docker/volumes 2> /dev/null
			mkdir -p $OUTPUT_DIR/containers/docker/swarm 2> /dev/null
			mkdir -p $OUTPUT_DIR/containers/docker/compose 2> /dev/null
			
			docker version 1> $OUTPUT_DIR/containers/docker/runtime/version.txt 2> /dev/null
			docker info 1> $OUTPUT_DIR/containers/docker/runtime/info.txt 2> /dev/null
			docker system df 1> $OUTPUT_DIR/containers/docker/runtime/system_df.txt 2> /dev/null
			
			# Extract key information from docker info
			docker info 2> /dev/null | grep "Version" > $OUTPUT_DIR/containers/docker/runtime/version_info.txt 2> /dev/null
			docker info 2> /dev/null | grep "Storage" > $OUTPUT_DIR/containers/docker/runtime/storage_info.txt 2> /dev/null
			docker info 2> /dev/null | grep "Runtime" > $OUTPUT_DIR/containers/docker/runtime/runtime_info.txt 2> /dev/null
			docker info 2> /dev/null | grep "Root" > $OUTPUT_DIR/containers/docker/runtime/root_info.txt 2> /dev/null
			docker info 2> /dev/null | grep "Registry" > $OUTPUT_DIR/containers/docker/runtime/registry_info.txt 2> /dev/null
			
			docker events --since 360h --until now 2>&1  > $OUTPUT_DIR/containers/docker/runtime/events_360h.txt 2> /dev/null

			if [ -f "/etc/docker/daemon.json" ]
			then
				cp /etc/docker/daemon.json $OUTPUT_DIR/containers/docker/config/daemon.json 2> /dev/null
			fi
			
			if [ -d "/etc/docker" ]
			then
				ls -la /etc/docker/ > $OUTPUT_DIR/containers/docker/config/etc_docker_listing.txt 2> /dev/null
				if [ -d "/etc/docker/certs.d" ]
				then
					find /etc/docker/certs.d -type f -name "*.crt" > $OUTPUT_DIR/containers/docker/config/cert_files.txt 2> /dev/null
					find /etc/docker/certs.d -type f -name "*.cert" >> $OUTPUT_DIR/containers/docker/config/cert_files.txt 2> /dev/null
					find /etc/docker/certs.d -type f -name "*.key" > $OUTPUT_DIR/containers/docker/config/key_files.txt 2> /dev/null
				fi
			fi
			
			docker info 2> /dev/null | grep "Docker Root Dir" | awk '{print $NF}' > $OUTPUT_DIR/containers/docker/config/docker_root_path.txt
			
			if [ -s "$OUTPUT_DIR/containers/docker/config/docker_root_path.txt" ]
			then
				DOCKER_ROOT=`cat $OUTPUT_DIR/containers/docker/config/docker_root_path.txt`
				if [ -n "$DOCKER_ROOT" ]
				then
					if [ -d "$DOCKER_ROOT" ]
					then
						echo "Docker Root Directory: $DOCKER_ROOT" > $OUTPUT_DIR/containers/docker/config/docker_root_info.txt
						df -h "$DOCKER_ROOT" >> $OUTPUT_DIR/containers/docker/config/docker_root_info.txt 2> /dev/null
						du -sh "$DOCKER_ROOT" >> $OUTPUT_DIR/containers/docker/config/docker_root_info.txt 2> /dev/null
						ls -la "$DOCKER_ROOT" >> $OUTPUT_DIR/containers/docker/config/docker_root_info.txt 2> /dev/null
					fi
				fi
			fi
			
			if [ -x "$(command -v systemctl)" ]
			then
				systemctl status docker > $OUTPUT_DIR/containers/docker/runtime/service_status.txt 2> /dev/null
				systemctl status docker.socket >> $OUTPUT_DIR/containers/docker/runtime/service_status.txt 2> /dev/null
				systemctl status containerd >> $OUTPUT_DIR/containers/docker/runtime/service_status.txt 2> /dev/null
			elif [ -x "$(command -v service)" ]
			then
				service docker status > $OUTPUT_DIR/containers/docker/runtime/service_status.txt 2> /dev/null
			elif [ -f "/etc/init.d/docker" ]
			then
				/etc/init.d/docker status > $OUTPUT_DIR/containers/docker/runtime/service_status.txt 2> /dev/null
			fi
			
			docker container ls --all --size 1> $OUTPUT_DIR/containers/docker/containers/all_containers.txt 2> /dev/null
			docker ps -a --no-trunc 1> $OUTPUT_DIR/containers/docker/containers/ps_all_no_trunc.txt 2> /dev/null
			docker stats --all --no-stream --no-trunc 1> $OUTPUT_DIR/containers/docker/containers/stats_all.txt 2> /dev/null
			
			docker ps -a -q 1> $OUTPUT_DIR/containers/docker/containers/container_ids.txt 2> /dev/null
			
			if [ -s "$OUTPUT_DIR/containers/docker/containers/container_ids.txt" ]
			then
				while read containerid
				do
					if [ -n "$containerid" ]
					then
						# Create safe filename from container ID (first 12 chars)
						safe_id=`echo "$containerid" | cut -c1-12`
						
						# Basic container info
						docker inspect "$containerid" > "$OUTPUT_DIR/containers/docker/containers/inspect_${safe_id}.json" 2> /dev/null
						docker top "$containerid" > "$OUTPUT_DIR/containers/docker/containers/processes_${safe_id}.txt" 2> /dev/null
						docker port "$containerid" > "$OUTPUT_DIR/containers/docker/containers/ports_${safe_id}.txt" 2> /dev/null
						
						# Container logs (limit size)
						docker logs "$containerid" 2>&1 | tail -1000 > "$OUTPUT_DIR/containers/docker/containers/logs_${safe_id}_tail1000.txt" 2> /dev/null
						
						# Filesystem changes (limit output)
						docker diff "$containerid" 2> /dev/null | head -5000 > "$OUTPUT_DIR/containers/docker/containers/diff_${safe_id}.txt" 2> /dev/null
						
						# Check if container is running before collecting stats
						docker ps -q 2> /dev/null | grep "^${containerid}" > /dev/null 2>&1
						if [ $? -eq 0 ]
						then
							docker stats "$containerid" --no-stream > "$OUTPUT_DIR/containers/docker/containers/stats_${safe_id}.txt" 2> /dev/null
						fi
					fi
				done < "$OUTPUT_DIR/containers/docker/containers/container_ids.txt"
			fi
			
			docker image ls --all 1> $OUTPUT_DIR/containers/docker/images/all_images.txt 2> /dev/null
			docker images -a --no-trunc 1> $OUTPUT_DIR/containers/docker/images/images_no_trunc.txt 2> /dev/null
			docker images --filter "dangling=true" 1> $OUTPUT_DIR/containers/docker/images/dangling_images.txt 2> /dev/null
			
			docker images -q 2> /dev/null | sort -u > $OUTPUT_DIR/containers/docker/images/image_ids.txt 2> /dev/null
			# Process all images
			if [ -s "$OUTPUT_DIR/containers/docker/images/image_ids.txt" ]
			then
				while read imageid
				do
					if [ -n "$imageid" ]
					then
						safe_id=`echo "$imageid" | cut -c1-12`
						docker image inspect "$imageid" > "$OUTPUT_DIR/containers/docker/images/inspect_${safe_id}.json" 2> /dev/null
						docker history "$imageid" --no-trunc > "$OUTPUT_DIR/containers/docker/images/history_${safe_id}.txt" 2> /dev/null
					fi
				done < "$OUTPUT_DIR/containers/docker/images/image_ids.txt"
			fi
			
			docker network ls 1> $OUTPUT_DIR/containers/docker/networks/all_networks.txt 2> /dev/null
			docker network ls -q > $OUTPUT_DIR/containers/docker/networks/network_ids.txt 2> /dev/null
			
			# Process each network
			if [ -s "$OUTPUT_DIR/containers/docker/networks/network_ids.txt" ]
			then
				while read netid
				do
					if [ -n "$netid" ]
					then
						safe_id=`echo "$netid" | cut -c1-12`
						docker network inspect "$netid" > "$OUTPUT_DIR/containers/docker/networks/inspect_${safe_id}.json" 2> /dev/null
					fi
				done < "$OUTPUT_DIR/containers/docker/networks/network_ids.txt"
			fi
			
			docker volume ls 1> $OUTPUT_DIR/containers/docker/volumes/all_volumes.txt 2> /dev/null
			
			docker volume ls -q 2> /dev/null > $OUTPUT_DIR/containers/docker/volumes/volume_names.txt 2> /dev/null
			
			# Process each volume
			if [ -s "$OUTPUT_DIR/containers/docker/volumes/volume_names.txt" ]
			then
				while read volname
				do
					if [ -n "$volname" ]
					then
						# Sanitize volume name for filename
						safe_name=`echo "$volname" | sed 's/[^a-zA-Z0-9._-]/_/g' | cut -c1-50`
						docker volume inspect "$volname" > "$OUTPUT_DIR/containers/docker/volumes/inspect_${safe_name}.json" 2> /dev/null
					fi
				done < "$OUTPUT_DIR/containers/docker/volumes/volume_names.txt"
			fi
			
			docker node ls > /dev/null 2>&1
			if [ $? -eq 0 ]
			then
				docker node ls 1> $OUTPUT_DIR/containers/docker/swarm/nodes.txt 2> /dev/null
				docker service ls 1> $OUTPUT_DIR/containers/docker/swarm/services.txt 2> /dev/null
				docker stack ls 1> $OUTPUT_DIR/containers/docker/swarm/stacks.txt 2> /dev/null
				docker secret ls 1> $OUTPUT_DIR/containers/docker/swarm/secrets_list.txt 2> /dev/null
				docker config ls 1> $OUTPUT_DIR/containers/docker/swarm/configs_list.txt 2> /dev/null
			fi

			if [ -x "$(command -v docker-compose)" ]
			then

				docker-compose version 1> $OUTPUT_DIR/containers/docker/compose/version.txt 2> /dev/null
				find /home -name "docker-compose.yml" 2> /dev/null > $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /home -name "docker-compose.yaml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /home -name "compose.yml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /home -name "compose.yaml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /root -name "docker-compose.yml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /root -name "docker-compose.yaml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /root -name "compose.yml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /root -name "compose.yaml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /opt -name "docker-compose.yml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /opt -name "docker-compose.yaml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /opt -name "compose.yml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /opt -name "compose.yaml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /srv -name "docker-compose.yml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /srv -name "docker-compose.yaml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /srv -name "compose.yml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				find /srv -name "compose.yaml" 2> /dev/null >> $OUTPUT_DIR/containers/docker/compose/compose_files_found.txt
				
				# Copy the actual compose files
				mkdir -p $OUTPUT_DIR/containers/docker/compose/files 2> /dev/null

				if [ -s "$OUTPUT_DIR/containers/docker/compose/compose_files_found.txt" ]
				then
					while read compose_file
					do
						if [ -f "$compose_file" ]
						then
							# Create safe filename preserving path information
							safe_path=`echo "$compose_file" | sed 's/\//_/g' | sed 's/^_//'`
							cp "$compose_file" "$OUTPUT_DIR/containers/docker/compose/files/${safe_path}" 2> /dev/null
							echo "$compose_file -> ${safe_path}" >> $OUTPUT_DIR/containers/docker/compose/files/path_mapping.txt
						fi
					done < "$OUTPUT_DIR/containers/docker/compose/compose_files_found.txt"
				fi
				
				if [ -s "$OUTPUT_DIR/containers/docker/compose/compose_files_found.txt" ]
				then
					while read compose_file
					do
						if [ -f "$compose_file" ]
						then
							compose_dir=`dirname "$compose_file"`
							if [ -f "$compose_dir/.env" ]
							then
								safe_path=`echo "$compose_dir/.env" | sed 's/\//_/g' | sed 's/^_//'`
								cp "$compose_dir/.env" "$OUTPUT_DIR/containers/docker/compose/files/${safe_path}" 2> /dev/null
								echo "$compose_dir/.env -> ${safe_path}" >> $OUTPUT_DIR/containers/docker/compose/files/env_files_mapping.txt
							fi
						fi
					done < "$OUTPUT_DIR/containers/docker/compose/compose_files_found.txt"
				fi
			fi
			
			docker plugin ls > $OUTPUT_DIR/containers/docker/runtime/plugins.txt 2> /dev/null
			docker buildx version > $OUTPUT_DIR/containers/docker/runtime/buildx_version.txt 2> /dev/null
			docker buildx ls > $OUTPUT_DIR/containers/docker/runtime/buildx_builders.txt 2> /dev/null
			docker info 2> /dev/null | grep -A 5 "Registry" > $OUTPUT_DIR/containers/docker/config/registries.txt 2> /dev/null
			docker info 2> /dev/null | grep "Storage Driver" > $OUTPUT_DIR/containers/docker/runtime/drivers_info.txt 2> /dev/null
			docker info 2> /dev/null | grep "Logging Driver" >> $OUTPUT_DIR/containers/docker/runtime/drivers_info.txt 2> /dev/null
			docker info 2> /dev/null | grep "Cgroup" >> $OUTPUT_DIR/containers/docker/runtime/drivers_info.txt 2> /dev/null
			docker info 2> /dev/null | grep "Runtime" >> $OUTPUT_DIR/containers/docker/runtime/drivers_info.txt 2> /dev/null
		fi

	if [ -x "$(command -v lxc)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting LXC/LXD information"
		mkdir -p $OUTPUT_DIR/containers/lxc 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/system 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/containers 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/images 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/networks 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/storage 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/profiles 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/cluster 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/config 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/logs 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/lxc/security 2> /dev/null
		
		lxc version > $OUTPUT_DIR/containers/lxc/system/version.txt 2> /dev/null
		lxc info > $OUTPUT_DIR/containers/lxc/system/info.txt 2> /dev/null
		lxc info --resources > $OUTPUT_DIR/containers/lxc/system/resources.txt 2> /dev/null
		lxc warning list --format compact > $OUTPUT_DIR/containers/lxc/system/warnings.txt 2> /dev/null
		lxc warning list --format yaml > $OUTPUT_DIR/containers/lxc/system/warnings.yaml 2> /dev/null
		
		# Global configuration
		lxc config show > $OUTPUT_DIR/containers/lxc/config/global_config.yaml 2> /dev/null
		
		# Remotes and authentication
		lxc remote list > $OUTPUT_DIR/containers/lxc/system/remote_list.txt 2> /dev/null
		lxc config trust list > $OUTPUT_DIR/containers/lxc/security/certificates.txt 2> /dev/null
		lxc config trust list --format yaml > $OUTPUT_DIR/containers/lxc/security/certificates.yaml 2> /dev/null
		
		# Aliases
		lxc alias list > $OUTPUT_DIR/containers/lxc/config/aliases.txt 2> /dev/null
		
		# Operations
		lxc operation list > $OUTPUT_DIR/containers/lxc/system/operations.txt 2> /dev/null
		lxc operation list --format yaml > $OUTPUT_DIR/containers/lxc/system/operations.yaml 2> /dev/null
		
		# Monitor sample (with timeout to prevent hanging)
		timeout 5 lxc monitor --type=lifecycle --pretty > $OUTPUT_DIR/containers/lxc/system/monitor_sample.txt 2>&1
		
		# Cluster information (if clustered)
		if lxc cluster list >/dev/null 2>&1; then
			lxc cluster list > $OUTPUT_DIR/containers/lxc/cluster/cluster_list.txt 2> /dev/null
			lxc cluster list --format yaml > $OUTPUT_DIR/containers/lxc/cluster/cluster_list.yaml 2> /dev/null
			lxc cluster show > $OUTPUT_DIR/containers/lxc/cluster/cluster_info.txt 2> /dev/null
		else
			echo "Not clustered" > $OUTPUT_DIR/containers/lxc/cluster/not_clustered.txt
		fi
		
		lxc list --all-projects --format compact > $OUTPUT_DIR/containers/lxc/containers/all_instances.txt 2> /dev/null
		lxc list --all-projects --format json > $OUTPUT_DIR/containers/lxc/containers/all_instances.json 2> /dev/null
		lxc list --all-projects --format yaml > $OUTPUT_DIR/containers/lxc/containers/all_instances.yaml 2> /dev/null
		
		lxc list --all-projects --format compact 2> /dev/null | sed 1d | awk '{print $1"|"$2}' > $OUTPUT_DIR/containers/lxc/containers/instance_list.txt
		
		# Process each container/VM
		while IFS='|' read -r name project; do
			if [ -n "$name" ] && [ "$name" != "NAME" ]; then
				
				# Create safe directory name
				SAFE_NAME=$(echo "$name" | sed 's/[^a-zA-Z0-9_-]/_/g')
				INSTANCE_DIR="$OUTPUT_DIR/containers/lxc/containers/${SAFE_NAME}"
				mkdir -p "$INSTANCE_DIR" 2> /dev/null
				
				# Set project context if needed
				if [ -n "$project" ] && [ "$project" != "default" ]; then
					PROJECT_FLAG="--project=$project"
				else
					PROJECT_FLAG=""
				fi
				
				# Basic information
				lxc info $PROJECT_FLAG "$name" > "$INSTANCE_DIR/info.txt" 2> /dev/null
				lxc info $PROJECT_FLAG "$name" --show-log > "$INSTANCE_DIR/info_with_log.txt" 2> /dev/null
				lxc info $PROJECT_FLAG "$name" --resources > "$INSTANCE_DIR/resources.txt" 2> /dev/null
				
				# Configuration
				lxc config show $PROJECT_FLAG "$name" > "$INSTANCE_DIR/config.yaml" 2> /dev/null
				lxc config show $PROJECT_FLAG "$name" --expanded > "$INSTANCE_DIR/config_expanded.yaml" 2> /dev/null
				
				# Metadata
				lxc config metadata show $PROJECT_FLAG "$name" > "$INSTANCE_DIR/metadata.yaml" 2> /dev/null
				
				# Devices
				lxc config device list $PROJECT_FLAG "$name" > "$INSTANCE_DIR/devices.txt" 2> /dev/null
				lxc config device show $PROJECT_FLAG "$name" > "$INSTANCE_DIR/devices_detail.yaml" 2> /dev/null
				
				# Snapshots
				lxc snapshot list $PROJECT_FLAG "$name" > "$INSTANCE_DIR/snapshots.txt" 2> /dev/null
				lxc info $PROJECT_FLAG "$name" 2> /dev/null | grep -A 50 "Snapshots:" > "$INSTANCE_DIR/snapshots_detail.txt" 2> /dev/null
				
				# If running, get additional info
				if lxc info $PROJECT_FLAG "$name" 2> /dev/null | grep -q "Status: Running"; then
					# Process information
					lxc info $PROJECT_FLAG "$name" 2> /dev/null | grep -A 20 "Processes:" > "$INSTANCE_DIR/processes.txt" 2> /dev/null
					
					# Try to get /etc/passwd for user enumeration (if container)
					lxc file pull $PROJECT_FLAG "$name/etc/passwd" - > "$INSTANCE_DIR/passwd.txt" 2> /dev/null
					
					# Network information from inside
					lxc exec $PROJECT_FLAG "$name" -- ip addr show > "$INSTANCE_DIR/ip_addr.txt" 2> /dev/null
					lxc exec $PROJECT_FLAG "$name" -- netstat -tlnp > "$INSTANCE_DIR/netstat.txt" 2> /dev/null
				fi
				
				# State information
				echo "Project: ${project:-default}" > "$INSTANCE_DIR/state.txt"
				lxc info $PROJECT_FLAG "$name" 2> /dev/null | grep -E "^(Name|Location|Remote|Architecture|Created|Status|Type|Profiles|Description):" >> "$INSTANCE_DIR/state.txt"
			fi
		done < $OUTPUT_DIR/containers/lxc/containers/instance_list.txt
		
		lxc image list --format compact > $OUTPUT_DIR/containers/lxc/images/image_list.txt 2> /dev/null
		lxc image list --format json > $OUTPUT_DIR/containers/lxc/images/image_list.json 2> /dev/null
		lxc image list --format yaml > $OUTPUT_DIR/containers/lxc/images/image_list.yaml 2> /dev/null
		
		lxc image list --format compact 2> /dev/null | sed 1d | awk '{print $2}' | while read imageid; do
			if [ -n "$imageid" ]; then
				SAFE_IMAGE=$(echo "$imageid" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-64)
				
				lxc image info "$imageid" > "$OUTPUT_DIR/containers/lxc/images/info_${SAFE_IMAGE}.txt" 2> /dev/null
				lxc image show "$imageid" > "$OUTPUT_DIR/containers/lxc/images/show_${SAFE_IMAGE}.yaml" 2> /dev/null
			fi
		done
		
		lxc network list > $OUTPUT_DIR/containers/lxc/networks/network_list.txt 2> /dev/null
		lxc network list --format yaml > $OUTPUT_DIR/containers/lxc/networks/network_list.yaml 2> /dev/null
		
		lxc network list --format compact 2> /dev/null | sed 1d | awk '{print $1}' | while read netname; do
			if [ -n "$netname" ]; then
				SAFE_NET=$(echo "$netname" | sed 's/[^a-zA-Z0-9_-]/_/g')
				mkdir -p "$OUTPUT_DIR/containers/lxc/networks/$SAFE_NET" 2> /dev/null
				
				lxc network show "$netname" > "$OUTPUT_DIR/containers/lxc/networks/$SAFE_NET/config.yaml" 2> /dev/null
				lxc network info "$netname" > "$OUTPUT_DIR/containers/lxc/networks/$SAFE_NET/info.txt" 2> /dev/null
				lxc network list-leases "$netname" > "$OUTPUT_DIR/containers/lxc/networks/$SAFE_NET/leases.txt" 2> /dev/null
			fi
		done
		
		lxc storage list --format compact > $OUTPUT_DIR/containers/lxc/storage/storage_list.txt 2> /dev/null
		lxc storage list --format yaml > $OUTPUT_DIR/containers/lxc/storage/storage_list.yaml 2> /dev/null
		
		lxc storage list --format compact 2> /dev/null | sed 1d | awk '{print $1}' | while read storageid; do
			if [ -n "$storageid" ]; then
				SAFE_STORAGE=$(echo "$storageid" | sed 's/[^a-zA-Z0-9_-]/_/g')
				mkdir -p "$OUTPUT_DIR/containers/lxc/storage/$SAFE_STORAGE" 2> /dev/null
				
				lxc storage show "$storageid" > "$OUTPUT_DIR/containers/lxc/storage/$SAFE_STORAGE/config.yaml" 2> /dev/null
				lxc storage info "$storageid" > "$OUTPUT_DIR/containers/lxc/storage/$SAFE_STORAGE/info.txt" 2> /dev/null
				lxc storage volume list "$storageid" > "$OUTPUT_DIR/containers/lxc/storage/$SAFE_STORAGE/volumes.txt" 2> /dev/null
				lxc storage volume list "$storageid" --format yaml > "$OUTPUT_DIR/containers/lxc/storage/$SAFE_STORAGE/volumes.yaml" 2> /dev/null
			fi
		done
		
		lxc profile list --format compact > $OUTPUT_DIR/containers/lxc/profiles/profile_list.txt 2> /dev/null
		lxc profile list --format yaml > $OUTPUT_DIR/containers/lxc/profiles/profile_list.yaml 2> /dev/null
		
		lxc profile list --format compact 2> /dev/null | sed 1d | awk '{print $1}' | while read profile; do
			if [ -n "$profile" ]; then
				SAFE_PROFILE=$(echo "$profile" | sed 's/[^a-zA-Z0-9_-]/_/g')
				
				lxc profile show "$profile" > "$OUTPUT_DIR/containers/lxc/profiles/profile_${SAFE_PROFILE}.yaml" 2> /dev/null
			fi
		done
		
		if [ -d "/var/lib/lxd" ]; then
			ls -la /var/lib/lxd/ > $OUTPUT_DIR/containers/lxc/system/var_lib_lxd_listing.txt 2> /dev/null
			
			find /var/lib/lxd/logs -name "*.log" -type f -mtime -7 2> /dev/null | head -50 | while read logfile; do
				if [ -f "$logfile" ]; then
					LOG_NAME=$(echo "$logfile" | sed 's|/var/lib/lxd/logs/||' | sed 's|/|_|g')
					cat "$logfile" > "$OUTPUT_DIR/containers/lxc/logs/recent_${LOG_NAME}" 2> /dev/null
				fi
			done
			
			# Database location
			if [ -f "/var/lib/lxd/database/global/db.bin" ]; then
				ls -la /var/lib/lxd/database/global/ > $OUTPUT_DIR/containers/lxc/system/database_listing.txt 2> /dev/null
			fi
		fi
		
		# Alternative log location
		if [ -d "/var/log/lxd" ]; then
			ls -la /var/log/lxd/ > $OUTPUT_DIR/containers/lxc/logs/log_directory_listing.txt 2> /dev/null
			
			# Copy recent daemon logs
			for log in lxd.log lxd.log.1; do
				if [ -f "/var/log/lxd/$log" ]; then
					cat "/var/log/lxd/$log" > "$OUTPUT_DIR/containers/lxc/logs/${log}_recent" 2> /dev/null
				fi
			done
		fi
		
		# Snap-specific paths (if LXD installed via snap)
		if [ -d "/var/snap/lxd" ]; then
			echo "LXD installed via snap" > $OUTPUT_DIR/containers/lxc/system/snap_install.txt
			ls -la /var/snap/lxd/common/lxd/ >> $OUTPUT_DIR/containers/lxc/system/snap_install.txt 2> /dev/null
		fi
		
		# Configuration files
		for conf_file in /etc/default/lxd /etc/default/lxd-bridge; do
			if [ -f "$conf_file" ]; then
				cp "$conf_file" "$OUTPUT_DIR/containers/lxc/config/" 2> /dev/null
			fi
		done
		
		SUMMARY="$OUTPUT_DIR/containers/lxc/SUMMARY.txt"
		echo "LXC/LXD Collection Summary" > "$SUMMARY"
		echo "==========================" >> "$SUMMARY"
		echo "Collection Date: $(date)" >> "$SUMMARY"
		echo "" >> "$SUMMARY"

		if [ -f "$OUTPUT_DIR/containers/lxc/system/version.txt" ]; then
			echo "Version:" >> "$SUMMARY"
			head -5 "$OUTPUT_DIR/containers/lxc/system/version.txt" >> "$SUMMARY"
			echo "" >> "$SUMMARY"
		fi
		
		# Resource counts
		if [ -f "$OUTPUT_DIR/containers/lxc/containers/instance_list.txt" ]; then
			INSTANCE_COUNT=$(wc -l < "$OUTPUT_DIR/containers/lxc/containers/instance_list.txt" 2> /dev/null || echo 0)
			echo "Total instances: $INSTANCE_COUNT" >> "$SUMMARY"
			
			# Count running instances
			RUNNING_COUNT=$(lxc list --all-projects 2> /dev/null | grep -c "RUNNING" || echo 0)
			echo "Running instances: $RUNNING_COUNT" >> "$SUMMARY"
		fi
		
		# Count resources
		IMAGE_COUNT=$(lxc image list 2> /dev/null | grep -c "^|" || echo 0)
		NETWORK_COUNT=$(lxc network list 2> /dev/null | grep -c "^|" || echo 0)
		STORAGE_COUNT=$(lxc storage list 2> /dev/null | grep -c "^|" || echo 0)
		PROFILE_COUNT=$(lxc profile list 2> /dev/null | grep -c "^|" || echo 0)
		
		echo "" >> "$SUMMARY"
		echo "Resources:" >> "$SUMMARY"
		echo "  Images: $IMAGE_COUNT" >> "$SUMMARY"
		echo "  Networks: $NETWORK_COUNT" >> "$SUMMARY"
		echo "  Storage pools: $STORAGE_COUNT" >> "$SUMMARY"
		echo "  Profiles: $PROFILE_COUNT" >> "$SUMMARY"
		
		# Cluster status
		if [ -f "$OUTPUT_DIR/containers/lxc/cluster/cluster_list.txt" ]; then
			echo "" >> "$SUMMARY"
			echo "Cluster: Yes" >> "$SUMMARY"
			CLUSTER_NODES=$(wc -l < "$OUTPUT_DIR/containers/lxc/cluster/cluster_list.txt" 2> /dev/null || echo 0)
			echo "Cluster nodes: $CLUSTER_NODES" >> "$SUMMARY"
		else
			echo "" >> "$SUMMARY"
			echo "Cluster: No" >> "$SUMMARY"
		fi
		
		# Warnings
		if [ -f "$OUTPUT_DIR/containers/lxc/system/warnings.txt" ]; then
			WARNING_COUNT=$(grep -c "^|" "$OUTPUT_DIR/containers/lxc/system/warnings.txt" 2> /dev/null || echo 0)
			if [ "$WARNING_COUNT" -gt 0 ]; then
				echo "" >> "$SUMMARY"
				echo "Warnings: $WARNING_COUNT (see system/warnings.txt)" >> "$SUMMARY"
			fi
		fi
		
		echo "" >> "$SUMMARY"
		echo "Collection completed. Check subdirectories for detailed information." >> "$SUMMARY"
	fi

	# Legacy LXC check (non-LXD)
	if [ -x "$(command -v lxc-ls)" ] && [ ! -x "$(command -v lxc)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting legacy LXC information"
		mkdir -p $OUTPUT_DIR/containers/legacy_lxc 2> /dev/null
		
		lxc-ls -f > $OUTPUT_DIR/containers/legacy_lxc/container_list.txt 2> /dev/null
		lxc-checkconfig > $OUTPUT_DIR/containers/legacy_lxc/checkconfig.txt 2> /dev/null
		lxc-version > $OUTPUT_DIR/containers/legacy_lxc/version.txt 2> /dev/null
		
		if [ -d "/var/lib/lxc" ]; then
			ls -la /var/lib/lxc/ > $OUTPUT_DIR/containers/legacy_lxc/var_lib_listing.txt 2> /dev/null
			
			# Collect container configs
			find /var/lib/lxc -name "config" -type f 2> /dev/null | while read cfg; do
				CONTAINER_NAME=$(echo "$cfg" | awk -F'/' '{print $(NF-1)}')
				mkdir -p "$OUTPUT_DIR/containers/legacy_lxc/containers/$CONTAINER_NAME" 2> /dev/null
				
				cp "$cfg" "$OUTPUT_DIR/containers/legacy_lxc/containers/$CONTAINER_NAME/config" 2> /dev/null
				
				# Get container info if running
				if lxc-info -n "$CONTAINER_NAME" >/dev/null 2>&1; then
					lxc-info -n "$CONTAINER_NAME" > "$OUTPUT_DIR/containers/legacy_lxc/containers/$CONTAINER_NAME/info.txt" 2> /dev/null
				fi
			done
		fi
		
		# Legacy LXC configuration
		if [ -f "/etc/lxc/default.conf" ]; then
			cp /etc/lxc/default.conf $OUTPUT_DIR/containers/legacy_lxc/ 2> /dev/null
		fi
		
		if [ -f "/etc/lxc/lxc.conf" ]; then
			cp /etc/lxc/lxc.conf $OUTPUT_DIR/containers/legacy_lxc/ 2> /dev/null
		fi
	fi
	
	# Check for Proxmox environment
	if [ -x "$(command -v pct)" ] || [ -x "$(command -v qm)" ] || [ -x "$(command -v pvesh)" ] || [ -d /etc/pve ]
	then
		echo "${COL_SECTION}PROXMOX VE INFORMATION:${RESET}"
		mkdir -p $OUTPUT_DIR/virtual/proxmox/system 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/cluster 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/nodes 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/storage 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/network 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/backup 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/config 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/access 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/firewall 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/ceph 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/zfs 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/tasks 2> /dev/null
		mkdir -p $OUTPUT_DIR/virtual/proxmox/vms 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/proxmox 2> /dev/null
		NODENAME=$(hostname)
		echo "Node name: $NODENAME" > $OUTPUT_DIR/virtual/proxmox/system/node_info.txt
		echo "Collection date: $(date)" >> $OUTPUT_DIR/virtual/proxmox/system/node_info.txt
		if [ -x "$(command -v pveversion)" ]; then
			pveversion > $OUTPUT_DIR/virtual/proxmox/system/version.txt 2> /dev/null
			pveversion --verbose > $OUTPUT_DIR/virtual/proxmox/system/version_verbose.txt 2> /dev/null
		fi
		if [ -x "$(command -v pvereport)" ]; then
			pvereport > $OUTPUT_DIR/virtual/proxmox/system/pvereport_full.txt 2> /dev/null
		fi
		if [ -f /etc/pve/subscription ]; then
			cp /etc/pve/subscription $OUTPUT_DIR/virtual/proxmox/system/subscription.txt 2> /dev/null
		fi
		if [ -x "$(command -v pvesubscription)" ]; then
			pvesubscription get > $OUTPUT_DIR/virtual/proxmox/system/subscription_status.txt 2> /dev/null
		fi
		if [ -x "$(command -v pvecm)" ]; then
			pvecm status > $OUTPUT_DIR/virtual/proxmox/cluster/pvecm_status.txt 2> /dev/null
			pvecm nodes > $OUTPUT_DIR/virtual/proxmox/cluster/pvecm_nodes.txt 2> /dev/null
		fi
		if [ -x "$(command -v corosync-cfgtool)" ]; then
			corosync-cfgtool -s > $OUTPUT_DIR/virtual/proxmox/cluster/corosync_status.txt 2> /dev/null
			corosync-cmapctl > $OUTPUT_DIR/virtual/proxmox/cluster/corosync_config.txt 2> /dev/null
		fi
		if [ -x "$(command -v pvesm)" ]; then
			pvesm status > $OUTPUT_DIR/virtual/proxmox/storage/storage_status.txt 2> /dev/null
			pvesm list local > $OUTPUT_DIR/virtual/proxmox/storage/storage_list_local.txt 2> /dev/null
			pvesm status 2> /dev/null | tail -n +2 | awk '{print $1}' | while read storage; do
				if [ -n "$storage" ]; then
					pvesm list "$storage" > "$OUTPUT_DIR/virtual/proxmox/storage/content_${storage}.txt" 2> /dev/null
					if [ -x "$(command -v pvesh)" ]; then
						pvesh get /storage/$storage --output-format json > "$OUTPUT_DIR/virtual/proxmox/storage/config_${storage}.json" 2> /dev/null
					fi
				fi
			done
		fi
		if [ -f /etc/network/interfaces ]; then
			cp /etc/network/interfaces $OUTPUT_DIR/virtual/proxmox/network/interfaces.txt 2> /dev/null
		fi
		if [ -d /etc/pve/nodes ]; then
			find /etc/pve/nodes -name "network" -type f 2> /dev/null | while read netconf; do
				node=$(echo "$netconf" | awk -F'/' '{print $(NF-1)}')
				cp "$netconf" "$OUTPUT_DIR/virtual/proxmox/network/network_${node}.txt" 2> /dev/null
			done
		fi
		brctl show > $OUTPUT_DIR/virtual/proxmox/network/bridges.txt 2> /dev/null
		ip link show type bridge > $OUTPUT_DIR/virtual/proxmox/network/bridges_ip.txt 2> /dev/null
		if [ -d /proc/net/bonding ]; then
			for bond in /proc/net/bonding/*; do
				if [ -f "$bond" ]; then
					echo "=== Bond: $(basename $bond) ===" >> $OUTPUT_DIR/virtual/proxmox/network/bonding.txt
					cat "$bond" >> $OUTPUT_DIR/virtual/proxmox/network/bonding.txt 2> /dev/null
					echo "" >> $OUTPUT_DIR/virtual/proxmox/network/bonding.txt
				fi
			done
		fi
		if [ -x "$(command -v ovs-vsctl)" ]; then
			ovs-vsctl show > $OUTPUT_DIR/virtual/proxmox/network/openvswitch.txt 2> /dev/null
			ovs-vsctl list-br > $OUTPUT_DIR/virtual/proxmox/network/ovs_bridges.txt 2> /dev/null
		fi
		if [ -x "$(command -v pve-firewall)" ]; then
			pve-firewall compile > $OUTPUT_DIR/virtual/proxmox/firewall/compiled_rules.txt 2> /dev/null
			pve-firewall status > $OUTPUT_DIR/virtual/proxmox/firewall/status.txt 2> /dev/null
		fi
		if [ -f /etc/pve/vzdump.cron ]; then
			cp /etc/pve/vzdump.cron $OUTPUT_DIR/virtual/proxmox/backup/vzdump_cron.txt 2> /dev/null
		fi
		if [ -f /etc/vzdump.conf ]; then
			cp /etc/vzdump.conf $OUTPUT_DIR/virtual/proxmox/backup/vzdump_config.txt 2> /dev/null
		fi
		if [ -x "$(command -v pct)" ]
		then
			pct list > $OUTPUT_DIR/containers/proxmox/container_list.txt 2> /dev/null
			pct list --format json > $OUTPUT_DIR/containers/proxmox/container_list.json 2> /dev/null
			pct cpusets > $OUTPUT_DIR/containers/proxmox/cpusets.txt 2> /dev/null
			pct list 2> /dev/null | sed -e '1d' | awk '{print $1}' > $OUTPUT_DIR/containers/proxmox/container_ids.txt
			while read -r containerid; do
				if [ -n "$containerid" ]; then
					mkdir -p "$OUTPUT_DIR/containers/proxmox/ct_$containerid" 2> /dev/null
					pct config "$containerid" > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/config.txt" 2> /dev/null
					pct status "$containerid" > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/status.txt" 2> /dev/null
					pct pending "$containerid" > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/pending.txt" 2> /dev/null
					pct listsnapshot "$containerid" > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/snapshots.txt" 2> /dev/null
					if pct status "$containerid" 2> /dev/null | grep -q "running"; then
						pct df "$containerid" > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/disk_usage.txt" 2> /dev/null
					fi
					if [ -x "$(command -v pvesh)" ]; then
						pvesh get /nodes/$NODENAME/lxc/$containerid/status/current --output-format json > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/status.json" 2> /dev/null
						pvesh get /nodes/$NODENAME/lxc/$containerid/config --output-format json > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/config.json" 2> /dev/null
						pvesh get /nodes/$NODENAME/lxc/$containerid/rrddata --output-format json > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/rrddata.json" 2> /dev/null
						pvesh get /nodes/$NODENAME/lxc/$containerid/firewall/options > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/firewall_options.txt" 2> /dev/null
						pvesh get /nodes/$NODENAME/lxc/$containerid/firewall/rules > "$OUTPUT_DIR/containers/proxmox/ct_$containerid/firewall_rules.txt" 2> /dev/null
					fi
				fi
			done < $OUTPUT_DIR/containers/proxmox/container_ids.txt
		fi
		if [ -x "$(command -v qm)" ]
		then
			qm list > $OUTPUT_DIR/virtual/proxmox/vms/vm_list.txt 2> /dev/null
			qm list --full > $OUTPUT_DIR/virtual/proxmox/vms/vm_list_full.txt 2> /dev/null
			qm list 2> /dev/null | sed -e '1d' | awk '{print $1}' > $OUTPUT_DIR/virtual/proxmox/vms/vm_ids.txt
			while read -r vmid; do
				if [ -n "$vmid" ]; then
					mkdir -p "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid" 2> /dev/null
					qm config "$vmid" > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/config.txt" 2> /dev/null
					qm status "$vmid" --verbose > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/status_verbose.txt" 2> /dev/null
					qm pending "$vmid" > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/pending.txt" 2> /dev/null
					qm listsnapshot "$vmid" > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/snapshots.txt" 2> /dev/null
					qm cloudinit dump "$vmid" > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/cloudinit.txt" 2> /dev/null
					qm agent "$vmid" ping > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/agent_ping.txt" 2> /dev/null
					if [ -x "$(command -v pvesh)" ]; then
						pvesh get /nodes/$NODENAME/qemu/$vmid/status/current --output-format json > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/status.json" 2> /dev/null
						pvesh get /nodes/$NODENAME/qemu/$vmid/config --output-format json > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/config.json" 2> /dev/null
						pvesh get /nodes/$NODENAME/qemu/$vmid/rrddata --output-format json > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/rrddata.json" 2> /dev/null
						pvesh get /nodes/$NODENAME/qemu/$vmid/agent/info > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/agent_info.txt" 2> /dev/null
						pvesh get /nodes/$NODENAME/qemu/$vmid/firewall/options > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/firewall_options.txt" 2> /dev/null
						pvesh get /nodes/$NODENAME/qemu/$vmid/firewall/rules > "$OUTPUT_DIR/virtual/proxmox/vms/vm_$vmid/firewall_rules.txt" 2> /dev/null
					fi
				fi
			done < $OUTPUT_DIR/virtual/proxmox/vms/vm_ids.txt
		fi

		if [ -x "$(command -v pvesh)" ]
		then
			pvesh get /nodes --output-format json > $OUTPUT_DIR/virtual/proxmox/nodes/all_nodes.json 2> /dev/null
			pvesh get /nodes --noborder > $OUTPUT_DIR/virtual/proxmox/nodes/all_nodes.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/status --output-format json > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_status.json 2> /dev/null
			pvesh get /nodes/$NODENAME/services > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_services.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/hardware/pci --noborder > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_hardware_pci.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/aplinfo > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_aplinfo.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/report > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_report.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/certificates/info > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_certificates.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/dns > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_dns.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/hosts > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_hosts.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/time > $OUTPUT_DIR/virtual/proxmox/nodes/${NODENAME}_time.txt 2> /dev/null
			pvesh get /nodes/$NODENAME/network --output-format json > $OUTPUT_DIR/virtual/proxmox/network/api_network.json 2> /dev/null
			pvesh get /nodes/$NODENAME/tasks --limit 500 --output-format json > $OUTPUT_DIR/virtual/proxmox/tasks/recent_tasks.json 2> /dev/null
			pvesh get /nodes/$NODENAME/tasks --limit 100 --noborder > $OUTPUT_DIR/virtual/proxmox/tasks/recent_tasks.txt 2> /dev/null
			pvesh get /storage --output-format json > $OUTPUT_DIR/virtual/proxmox/storage/api_storage.json 2> /dev/null
			pvesh get /nodes/$NODENAME/storage --output-format json > $OUTPUT_DIR/virtual/proxmox/storage/node_storage.json 2> /dev/null
			pvesh get /cluster/status --output-format json > $OUTPUT_DIR/virtual/proxmox/cluster/status.json 2> /dev/null
			pvesh get /cluster/config/nodes > $OUTPUT_DIR/virtual/proxmox/cluster/config_nodes.txt 2> /dev/null
			pvesh get /cluster/resources --output-format json > $OUTPUT_DIR/virtual/proxmox/cluster/resources.json 2> /dev/null
			pvesh get /cluster/options > $OUTPUT_DIR/virtual/proxmox/cluster/options.txt 2> /dev/null
			pvesh get /cluster/nextid > $OUTPUT_DIR/virtual/proxmox/cluster/nextid.txt 2> /dev/null
			pvesh get /cluster/ha/status/current > $OUTPUT_DIR/virtual/proxmox/cluster/ha_status_current.txt 2> /dev/null
			pvesh get /cluster/ha/status/manager_status > $OUTPUT_DIR/virtual/proxmox/cluster/ha_manager_status.txt 2> /dev/null
			pvesh get /cluster/ha/resources > $OUTPUT_DIR/virtual/proxmox/cluster/ha_resources.txt 2> /dev/null
			pvesh get /cluster/ha/groups > $OUTPUT_DIR/virtual/proxmox/cluster/ha_groups.txt 2> /dev/null
			pvesh get /cluster/firewall/options > $OUTPUT_DIR/virtual/proxmox/firewall/cluster_options.txt 2> /dev/null
			pvesh get /cluster/firewall/groups > $OUTPUT_DIR/virtual/proxmox/firewall/cluster_groups.txt 2> /dev/null
			pvesh get /cluster/firewall/rules > $OUTPUT_DIR/virtual/proxmox/firewall/cluster_rules.txt 2> /dev/null
			pvesh get /cluster/firewall/aliases > $OUTPUT_DIR/virtual/proxmox/firewall/cluster_aliases.txt 2> /dev/null
			pvesh get /cluster/firewall/ipset > $OUTPUT_DIR/virtual/proxmox/firewall/cluster_ipset.txt 2> /dev/null
			pvesh get /cluster/backup --output-format json > $OUTPUT_DIR/virtual/proxmox/backup/jobs.json 2> /dev/null
			pvesh get /cluster/backup --noborder > $OUTPUT_DIR/virtual/proxmox/backup/jobs.txt 2> /dev/null
			pvesh get /cluster/replication --output-format json > $OUTPUT_DIR/virtual/proxmox/backup/replication.json 2> /dev/null
			pvesh get /access/users --output-format json > $OUTPUT_DIR/virtual/proxmox/access/users.json 2> /dev/null
			pvesh get /access/groups --output-format json > $OUTPUT_DIR/virtual/proxmox/access/groups.json 2> /dev/null
			pvesh get /access/roles > $OUTPUT_DIR/virtual/proxmox/access/roles.txt 2> /dev/null
			pvesh get /access/domains > $OUTPUT_DIR/virtual/proxmox/access/auth_domains.txt 2> /dev/null
			pvesh get /access/acl > $OUTPUT_DIR/virtual/proxmox/access/acl.txt 2> /dev/null
			pvesh get /access/permissions > $OUTPUT_DIR/virtual/proxmox/access/permissions.txt 2> /dev/null
			pvesh get /pools --output-format json > $OUTPUT_DIR/virtual/proxmox/access/pools.json 2> /dev/null
		fi

		if [ -d /etc/pve ]
		then
			find /etc/pve -type f -readable 2> /dev/null | sort > $OUTPUT_DIR/virtual/proxmox/config/pve_file_listing.txt
			for config_file in \
				/etc/pve/corosync.conf \
				/etc/pve/datacenter.cfg \
				/etc/pve/storage.cfg \
				/etc/pve/user.cfg \
				/etc/pve/domains.cfg \
				/etc/pve/authkey.pub \
				/etc/pve/pve-root-ca.pem \
				/etc/pve/status.cfg \
				/etc/pve/.version \
				/etc/pve/.members \
				/etc/pve/.vmlist
			do
				if [ -r "$config_file" ]; then
					dest_file="$OUTPUT_DIR/virtual/proxmox/config/$(basename $config_file)"
					cp "$config_file" "$dest_file" 2> /dev/null
				fi
			done
			if [ -d /etc/pve/ha ]; then
				mkdir -p $OUTPUT_DIR/virtual/proxmox/config/ha 2> /dev/null
				for ha_file in /etc/pve/ha/*; do
					if [ -r "$ha_file" ]; then
						cp "$ha_file" $OUTPUT_DIR/virtual/proxmox/config/ha/ 2> /dev/null
					fi
				done
			fi
			if [ -d /etc/pve/firewall ]; then
				mkdir -p $OUTPUT_DIR/virtual/proxmox/config/firewall 2> /dev/null
				find /etc/pve/firewall -type f -readable -exec cp {} $OUTPUT_DIR/virtual/proxmox/config/firewall/ \; 2> /dev/null
			fi
			if [ -d "/etc/pve/nodes/$NODENAME" ]; then
				mkdir -p "$OUTPUT_DIR/virtual/proxmox/config/node_$NODENAME" 2> /dev/null
				find "/etc/pve/nodes/$NODENAME" -type f -readable 2> /dev/null | while read file; do
					rel_path=$(echo "$file" | sed "s|/etc/pve/nodes/$NODENAME/||")
					dest_dir="$OUTPUT_DIR/virtual/proxmox/config/node_$NODENAME/$(dirname "$rel_path")"
					mkdir -p "$dest_dir" 2> /dev/null
					cp "$file" "$dest_dir/" 2> /dev/null
				done
			fi
		fi
		
		for sysconf in \
			/etc/default/pveproxy \
			/etc/default/pvedaemon \
			/etc/default/pve-ha-crm \
			/etc/default/pve-ha-lrm \
			/etc/default/qemu-server \
			/etc/vzdump.conf \
			/etc/qemu-server.conf
		do
			if [ -f "$sysconf" ]; then
				cp "$sysconf" "$OUTPUT_DIR/virtual/proxmox/config/" 2> /dev/null
			fi
		done
		
		if [ -x "$(command -v ceph)" ] && [ -f /etc/pve/ceph.conf ]
		then
			ceph -s > $OUTPUT_DIR/virtual/proxmox/ceph/status.txt 2> /dev/null
			ceph health detail > $OUTPUT_DIR/virtual/proxmox/ceph/health_detail.txt 2> /dev/null
			ceph osd tree > $OUTPUT_DIR/virtual/proxmox/ceph/osd_tree.txt 2> /dev/null
			ceph osd df > $OUTPUT_DIR/virtual/proxmox/ceph/osd_df.txt 2> /dev/null
			ceph df > $OUTPUT_DIR/virtual/proxmox/ceph/df.txt 2> /dev/null
			ceph mon stat > $OUTPUT_DIR/virtual/proxmox/ceph/mon_stat.txt 2> /dev/null
			ceph pg stat > $OUTPUT_DIR/virtual/proxmox/ceph/pg_stat.txt 2> /dev/null
			cp /etc/pve/ceph.conf $OUTPUT_DIR/virtual/proxmox/ceph/ceph.conf 2> /dev/null
	
			if [ -x "$(command -v pvesh)" ]; then
				pvesh get /nodes/$NODENAME/ceph/status > $OUTPUT_DIR/virtual/proxmox/ceph/pvesh_status.txt 2> /dev/null
				pvesh get /nodes/$NODENAME/ceph/pools > $OUTPUT_DIR/virtual/proxmox/ceph/pvesh_pools.txt 2> /dev/null
			fi
		fi
		
		if [ -x "$(command -v zfs)" ]
		then
			zfs list -t all > $OUTPUT_DIR/virtual/proxmox/zfs/list_all.txt 2> /dev/null
			zpool list -v > $OUTPUT_DIR/virtual/proxmox/zfs/pool_list.txt 2> /dev/null
			zpool status -v > $OUTPUT_DIR/virtual/proxmox/zfs/pool_status.txt 2> /dev/null
			zpool history > $OUTPUT_DIR/virtual/proxmox/zfs/pool_history.txt 2> /dev/null
			zfs get all > $OUTPUT_DIR/virtual/proxmox/zfs/properties_all.txt 2> /dev/null
		fi
		
		if [ -d /var/log/pve ]
		then
			mkdir -p $OUTPUT_DIR/logs/proxmox 2> /dev/null

			for logfile in \
				/var/log/pve/tasks/active \
				/var/log/pve-firewall.log \
				/var/log/pveproxy/access.log \
				/var/log/pvedaemon.log
			do
				if [ -f "$logfile" ]; then
					tail -30000 "$logfile" > "$OUTPUT_DIR/logs/proxmox/$(basename $logfile)_recent.log" 2> /dev/null
				fi
			done
			
			find /var/log/pve/tasks -type f -mtime -7 -name "UPID*" 2> /dev/null | tail -100 | while read tasklog; do
				cp "$tasklog" "$OUTPUT_DIR/logs/proxmox/" 2> /dev/null
			done
		fi
		
		for service in \
			pve-cluster \
			pvedaemon \
			pveproxy \
			pvestatd \
			pve-ha-crm \
			pve-ha-lrm \
			pve-firewall \
			corosync \
			ceph-mon@$NODENAME \
			ceph-mgr@$NODENAME \
			ceph-osd
		do
			systemctl status $service --no-pager > "$OUTPUT_DIR/virtual/proxmox/system/service_${service}.txt" 2> /dev/null
		done
		
		SUMMARY="$OUTPUT_DIR/virtual/proxmox/SUMMARY.txt"
		echo "Proxmox VE Collection Summary" > "$SUMMARY"
		echo "=============================" >> "$SUMMARY"
		echo "Collection Date: $(date)" >> "$SUMMARY"
		echo "Node: $NODENAME" >> "$SUMMARY"
		echo "" >> "$SUMMARY"
		
		if [ -f "$OUTPUT_DIR/virtual/proxmox/system/version.txt" ]; then
			echo "Version:" >> "$SUMMARY"
			cat "$OUTPUT_DIR/virtual/proxmox/system/version.txt" >> "$SUMMARY"
			echo "" >> "$SUMMARY"
		fi
		
		if [ -f "$OUTPUT_DIR/virtual/proxmox/vms/vm_ids.txt" ]; then
			VM_COUNT=$(wc -l < "$OUTPUT_DIR/virtual/proxmox/vms/vm_ids.txt" 2> /dev/null || echo 0)
			echo "Virtual Machines: $VM_COUNT" >> "$SUMMARY"
		fi
		
		if [ -f "$OUTPUT_DIR/containers/proxmox/container_ids.txt" ]; then
			CT_COUNT=$(wc -l < "$OUTPUT_DIR/containers/proxmox/container_ids.txt" 2> /dev/null || echo 0)
			echo "LXC Containers: $CT_COUNT" >> "$SUMMARY"
		fi
		
		if [ -x "$(command -v qm)" ]; then
			RUNNING_VMS=$(qm list 2> /dev/null | grep -c " running " || echo 0)
			echo "Running VMs: $RUNNING_VMS" >> "$SUMMARY"
		fi
		
		if [ -x "$(command -v pct)" ]; then
			RUNNING_CTS=$(pct list 2> /dev/null | grep -c " running " || echo 0)
			echo "Running Containers: $RUNNING_CTS" >> "$SUMMARY"
		fi
		
		if [ -f "$OUTPUT_DIR/virtual/proxmox/cluster/pvecm_status.txt" ]; then
			echo "" >> "$SUMMARY"
			echo "Cluster Status:" >> "$SUMMARY"
			grep -E "(Cluster information|Nodeid:|Nodes:|Quorum:)" "$OUTPUT_DIR/virtual/proxmox/cluster/pvecm_status.txt" >> "$SUMMARY" 2> /dev/null
		fi
		
		if [ -f "$OUTPUT_DIR/virtual/proxmox/storage/storage_status.txt" ]; then
			echo "" >> "$SUMMARY"
			echo "Storage Status:" >> "$SUMMARY"
			head -20 "$OUTPUT_DIR/virtual/proxmox/storage/storage_status.txt" >> "$SUMMARY" 2> /dev/null
		fi
		
		if [ -f "$OUTPUT_DIR/virtual/proxmox/system/subscription_status.txt" ]; then
			echo "" >> "$SUMMARY"
			echo "Subscription:" >> "$SUMMARY"
			grep -E "(status:|key:)" "$OUTPUT_DIR/virtual/proxmox/system/subscription_status.txt" >> "$SUMMARY" 2> /dev/null
		fi
	fi

	# OpenVZ legacy support (if present)
	if [ -x "$(command -v vzctl)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting OpenVZ information"
		mkdir -p $OUTPUT_DIR/containers/openvz 2> /dev/null
		
		vzctl list -a > $OUTPUT_DIR/containers/openvz/container_list.txt 2> /dev/null
		vzlist -a -o ctid,hostname,status,ip,diskspace,physpages > $OUTPUT_DIR/containers/openvz/detailed_list.txt 2> /dev/null
		
		vzlist -a -H -o ctid 2> /dev/null | while read ctid; do
			if [ -n "$ctid" ]; then
				mkdir -p "$OUTPUT_DIR/containers/openvz/ct_$ctid" 2> /dev/null
				vzctl status $ctid > "$OUTPUT_DIR/containers/openvz/ct_$ctid/status.txt" 2> /dev/null
				
				if [ -f "/etc/vz/conf/${ctid}.conf" ]; then
					cp "/etc/vz/conf/${ctid}.conf" "$OUTPUT_DIR/containers/openvz/ct_$ctid/config.conf" 2> /dev/null
				fi
			fi
		done
	fi

	if [ -x "$(command -v podman)" ]
	then
		echo "  ${COL_ENTRY}>${RESET} Collecting PODMAN information"
		mkdir -p $OUTPUT_DIR/containers/podman 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/system 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/containers 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/images 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/networks 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/volumes 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/pods 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/configs 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/logs 2> /dev/null
		mkdir -p $OUTPUT_DIR/containers/podman/systemd 2> /dev/null
		
		podman version > $OUTPUT_DIR/containers/podman/system/version.txt 2> /dev/null
		podman info > $OUTPUT_DIR/containers/podman/system/info.txt 2> /dev/null
		podman system info --format json > $OUTPUT_DIR/containers/podman/system/info.json 2> /dev/null
		podman system df > $OUTPUT_DIR/containers/podman/system/disk_usage.txt 2> /dev/null
		podman system prune --dry-run > $OUTPUT_DIR/containers/podman/system/prune_dryrun.txt 2> /dev/null
		
		timeout 60 podman events --since 72h --format json 2>&1 > $OUTPUT_DIR/containers/podman/system/events_72h.json 2> /dev/null
		timeout 60 podman events --since 360h --format json 2>&1 > $OUTPUT_DIR/containers/podman/system/events_360h.json 2> /dev/null
		
		if podman machine list &>/dev/null; then
			podman machine list > $OUTPUT_DIR/containers/podman/system/machine_list.txt 2> /dev/null
			podman machine info > $OUTPUT_DIR/containers/podman/system/machine_info.txt 2> /dev/null
		fi
		
		if [ "$EUID" -ne 0 ] 2> /dev/null || [ "$(id -u)" -ne 0 ] 2> /dev/null
		then
			echo "Running as rootless podman" > $OUTPUT_DIR/containers/podman/system/rootless_info.txt
			echo "User: $(id -un)" >> $OUTPUT_DIR/containers/podman/system/rootless_info.txt
			echo "UID: $(id -u)" >> $OUTPUT_DIR/containers/podman/system/rootless_info.txt
			podman unshare cat /proc/self/uid_map >> $OUTPUT_DIR/containers/podman/system/rootless_info.txt 2> /dev/null
			podman unshare cat /proc/self/gid_map >> $OUTPUT_DIR/containers/podman/system/rootless_info.txt 2> /dev/null
		else
			echo "Running as root" > $OUTPUT_DIR/containers/podman/system/root_info.txt
		fi
		
		podman container ls --all --size > $OUTPUT_DIR/containers/podman/containers/container_list.txt 2> /dev/null
		podman container ls --all --format json > $OUTPUT_DIR/containers/podman/containers/container_list.json 2> /dev/null
		podman container ps --all --format "{{.ID}}" > $OUTPUT_DIR/containers/podman/containers/container_ids.txt 2> /dev/null
		
		while read -r containerid; do
			if [ -n "$containerid" ]; then
				mkdir -p "$OUTPUT_DIR/containers/podman/containers/$containerid" 2> /dev/null
				podman inspect "$containerid" > "$OUTPUT_DIR/containers/podman/containers/$containerid/inspect.json" 2> /dev/null
				podman top "$containerid" > "$OUTPUT_DIR/containers/podman/containers/$containerid/processes.txt" 2> /dev/null
				podman stats "$containerid" --no-stream > "$OUTPUT_DIR/containers/podman/containers/$containerid/stats.txt" 2> /dev/null
				podman port "$containerid" > "$OUTPUT_DIR/containers/podman/containers/$containerid/ports.txt" 2> /dev/null
				podman logs "$containerid" --tail 5000 > "$OUTPUT_DIR/containers/podman/containers/$containerid/logs_tail.txt" 2> /dev/null
				podman diff "$containerid" > "$OUTPUT_DIR/containers/podman/containers/$containerid/filesystem_diff.txt" 2> /dev/null
				podman healthcheck run "$containerid" > "$OUTPUT_DIR/containers/podman/containers/$containerid/healthcheck.txt" 2> /dev/null
				podman inspect "$containerid" --format "{{json .Mounts}}" > "$OUTPUT_DIR/containers/podman/containers/$containerid/mounts.json" 2> /dev/null
				podman inspect "$containerid" --format "{{json .Config}}" > "$OUTPUT_DIR/containers/podman/containers/$containerid/config.json" 2> /dev/null
				podman inspect "$containerid" --format "{{json .HostConfig}}" > "$OUTPUT_DIR/containers/podman/containers/$containerid/hostconfig.json" 2> /dev/null
				podman inspect "$containerid" --format "{{json .NetworkSettings}}" > "$OUTPUT_DIR/containers/podman/containers/$containerid/network_settings.json" 2> /dev/null
			fi
		done < $OUTPUT_DIR/containers/podman/containers/container_ids.txt 2> /dev/null
		podman image ls --all > $OUTPUT_DIR/containers/podman/images/image_list.txt 2> /dev/null
		podman image ls --all --format json > $OUTPUT_DIR/containers/podman/images/image_list.json 2> /dev/null
		podman image ls --filter dangling=true > $OUTPUT_DIR/containers/podman/images/dangling_images.txt 2> /dev/null
		podman image ls --format "{{.ID}}" --no-trunc | sort -u > $OUTPUT_DIR/containers/podman/images/image_ids.txt 2> /dev/null
		while read -r imageid; do
			if [ -n "$imageid" ]; then
				# Create safe filename (replace : with _)
				SAFE_ID=$(echo "$imageid" | sed 's/[:]/_/g' | cut -c1-64)
				mkdir -p "$OUTPUT_DIR/containers/podman/images/$SAFE_ID" 2> /dev/null
				podman image inspect "$imageid" > "$OUTPUT_DIR/containers/podman/images/$SAFE_ID/inspect.json" 2> /dev/null
				podman image history "$imageid" > "$OUTPUT_DIR/containers/podman/images/$SAFE_ID/history.txt" 2> /dev/null
				podman image tree "$imageid" > "$OUTPUT_DIR/containers/podman/images/$SAFE_ID/tree.txt" 2> /dev/null
			fi
		done < $OUTPUT_DIR/containers/podman/images/image_ids.txt 2> /dev/null
		podman network ls > $OUTPUT_DIR/containers/podman/networks/network_list.txt 2> /dev/null
		podman network ls --format json > $OUTPUT_DIR/containers/podman/networks/network_list.json 2> /dev/null
		podman network ls --format "{{.Name}}" 2> /dev/null | while read netname; do
			if [ -n "$netname" ]; then
				SAFE_NAME=$(echo "$netname" | sed 's/[^a-zA-Z0-9_-]/_/g')
				podman network inspect "$netname" > "$OUTPUT_DIR/containers/podman/networks/network_${SAFE_NAME}.json" 2> /dev/null
			fi
		done
		podman volume ls > $OUTPUT_DIR/containers/podman/volumes/volume_list.txt 2> /dev/null
		podman volume ls --format json > $OUTPUT_DIR/containers/podman/volumes/volume_list.json 2> /dev/null
		podman volume ls --format "{{.Name}}" 2> /dev/null | while read volumeid; do
			if [ -n "$volumeid" ]; then
				SAFE_VOL=$(echo "$volumeid" | sed 's/[^a-zA-Z0-9_-]/_/g' | cut -c1-64)
				podman volume inspect "$volumeid" > "$OUTPUT_DIR/containers/podman/volumes/volume_${SAFE_VOL}.json" 2> /dev/null
			fi
		done
		podman pod ls > $OUTPUT_DIR/containers/podman/pods/pod_list.txt 2> /dev/null
		podman pod ls --format json > $OUTPUT_DIR/containers/podman/pods/pod_list.json 2> /dev/null
		
		podman pod ls --format "{{.ID}}" 2> /dev/null | while read podid; do
			if [ -n "$podid" ]; then
				mkdir -p "$OUTPUT_DIR/containers/podman/pods/$podid" 2> /dev/null	
				podman pod inspect "$podid" > "$OUTPUT_DIR/containers/podman/pods/$podid/inspect.json" 2> /dev/null
				podman pod stats "$podid" --no-stream > "$OUTPUT_DIR/containers/podman/pods/$podid/stats.txt" 2> /dev/null
				podman pod top "$podid" > "$OUTPUT_DIR/containers/podman/pods/$podid/processes.txt" 2> /dev/null
				podman pod ps "$podid" > "$OUTPUT_DIR/containers/podman/pods/$podid/containers.txt" 2> /dev/null
			fi
		done
		podman secret ls > $OUTPUT_DIR/containers/podman/system/secrets_list.txt 2> /dev/null
		if [ -d "$HOME/.config/containers" ]; then
			ls -la "$HOME/.config/containers/" > $OUTPUT_DIR/containers/podman/configs/user_config_listing.txt 2> /dev/null
			for conf in storage.conf containers.conf registries.conf mounts.conf
			do
				if [ -f "$HOME/.config/containers/$conf" ]; then
					cp "$HOME/.config/containers/$conf" "$OUTPUT_DIR/containers/podman/configs/user_$conf" 2> /dev/null
				fi
			done
		fi
		if [ -d "/etc/containers" ]; then
			ls -la /etc/containers/ > $OUTPUT_DIR/containers/podman/configs/system_config_listing.txt 2> /dev/null
			for conf in storage.conf containers.conf registries.conf policy.json mounts.conf
			do
				if [ -f "/etc/containers/$conf" ]; then
					cp "/etc/containers/$conf" "$OUTPUT_DIR/containers/podman/configs/system_$conf" 2> /dev/null
				fi
			done
			if [ -d "/etc/containers/registries.d" ]; then
				cp -r "/etc/containers/registries.d" "$OUTPUT_DIR/containers/podman/configs/" 2> /dev/null
			fi
		fi
		for cni_dir in /etc/cni/net.d "$HOME/.config/cni/net.d"
		do
			if [ -d "$cni_dir" ]; then
				echo "Found CNI config: $cni_dir" >> $OUTPUT_DIR/containers/podman/configs/cni_locations.txt
				ls -la "$cni_dir" >> $OUTPUT_DIR/containers/podman/configs/cni_locations.txt 2> /dev/null
			fi
		done
		if [ -d "$HOME/.config/systemd/user" ]; then
			find "$HOME/.config/systemd/user" -name "*podman*" -o -name "*container*" -ls > $OUTPUT_DIR/containers/podman/systemd/user_units.txt 2> /dev/null
			find "$HOME/.config/systemd/user" \( -name "*podman*.service" -o -name "*container*.service" \) -exec cp {} $OUTPUT_DIR/containers/podman/systemd/ \; 2> /dev/null
		fi
		for systemd_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system
		do
			if [ -d "$systemd_dir" ]; then
				find "$systemd_dir" -name "*podman*" -o -name "*container*" -ls >> $OUTPUT_DIR/containers/podman/systemd/system_units.txt 2> /dev/null
			fi
		done
		podman container ls --format "{{.Names}}" 2> /dev/null | while read cname; do
			if [ -n "$cname" ]; then
				SAFE_CNAME=$(echo "$cname" | sed 's/[^a-zA-Z0-9_-]/_/g')
				podman generate systemd "$cname" > "$OUTPUT_DIR/containers/podman/systemd/generated_${SAFE_CNAME}.service" 2> /dev/null
			fi
		done
		STORAGE_INFO="$OUTPUT_DIR/containers/podman/system/storage_info.txt"
		podman info --format "{{.Store.GraphRoot}}" > "$STORAGE_INFO" 2> /dev/null
		podman info --format "{{.Store.RunRoot}}" >> "$STORAGE_INFO" 2> /dev/null
		for storage_dir in "$HOME/.local/share/containers/storage" "/var/lib/containers/storage"
		do
			if [ -d "$storage_dir" ]; then
				echo "" >> "$STORAGE_INFO"
				echo "Storage directory: $storage_dir" >> "$STORAGE_INFO"
				du -sh "$storage_dir" >> "$STORAGE_INFO" 2> /dev/null
				ls -la "$storage_dir" >> "$STORAGE_INFO" 2> /dev/null
			fi
		done
		SUMMARY="$OUTPUT_DIR/containers/podman/SUMMARY.txt"
		echo "Podman Collection Summary" > "$SUMMARY"
		echo "========================" >> "$SUMMARY"
		echo "Collection Date: $(date)" >> "$SUMMARY"
		echo "" >> "$SUMMARY"
		podman version --format "Version: {{.Client.Version}}" >> "$SUMMARY" 2> /dev/null
		echo "" >> "$SUMMARY"
		CONTAINER_COUNT=$(wc -l < $OUTPUT_DIR/containers/podman/containers/container_ids.txt 2> /dev/null || echo 0)
		RUNNING_COUNT=$(podman ps -q | wc -l 2> /dev/null || echo 0)
		IMAGE_COUNT=$(wc -l < $OUTPUT_DIR/containers/podman/images/image_ids.txt 2> /dev/null || echo 0)
		NETWORK_COUNT=$(podman network ls -q | wc -l 2> /dev/null || echo 0)
		VOLUME_COUNT=$(podman volume ls -q | wc -l 2> /dev/null || echo 0)
		POD_COUNT=$(podman pod ls -q 2> /dev/null | wc -l || echo 0)
		echo "Resources:" >> "$SUMMARY"
		echo "  Total containers: $CONTAINER_COUNT (Running: $RUNNING_COUNT)" >> "$SUMMARY"
		echo "  Total images: $IMAGE_COUNT" >> "$SUMMARY"
		echo "  Networks: $NETWORK_COUNT" >> "$SUMMARY"
		echo "  Volumes: $VOLUME_COUNT" >> "$SUMMARY"
		echo "  Pods: $POD_COUNT" >> "$SUMMARY"
		if [ -f "$OUTPUT_DIR/containers/podman/system/disk_usage.txt" ]; then
			echo "" >> "$SUMMARY"
			echo "Disk Usage:" >> "$SUMMARY"
			grep -E "^(Images|Containers|Volumes|Total)" "$OUTPUT_DIR/containers/podman/system/disk_usage.txt" >> "$SUMMARY" 2> /dev/null
		fi
		echo "" >> "$SUMMARY"
		echo "Collection completed. Check subdirectories for detailed information." >> "$SUMMARY"
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
