#!/bin/sh

# --------------------------------------------------
# Simple forensic collector for UNIX servers
# Author: Jerzy 'Yuri' Kramarz 
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
#     > Mac
#     > Probably others as well.
# 
# Commandline Options
# ~~~~~~~~~~~~~~~~~~~
#
#    --platform=<solaris | hpup | mac | aix | linux | generic>
#    Specify a platform, instead of using the platform auto-
#    detection code.
#
#    --quiet
#    No questions will be asked, unless specified


# ---------------------------
# Global Variables
# ---------------------------
VERSION="1.1"
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
echo "  _   _ _   _ _____  __   ____ ___  _     _     _____ ____ _____ ___  ____  "
echo " | | | | \ | |_ _\ \/ /  / ___/ _ \| |   | |   | ____/ ___|_   _/ _ \|  _ \ "
echo " | | | |  \| || | \  /  | |  | | | | |   | |   |  _|| |     | || | | | |_) |"
echo " | |_| | |\  || | /  \  | |__| |_| | |___| |___| |__| |___  | || |_| |  _ < "
echo "  \___/|_| \_|___/_/\_\  \____\___/|_____|_____|_____\____| |_| \___/|_| \_\""
echo ""
echo "${COL_LOGO}Simple forensic collector for UNIX Systems $VERSION by op7ic"
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
echo "  ${COL_ENTRY}>${RESET} UNIX Collector"
echo $VERSION 1> $OUTPUT_DIR/collector-version.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} UNIX Collector Date"
echo $LONG_DATE 1> $OUTPUT_DIR/collector-date.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} UNIX Collector User"
id 1> $OUTPUT_DIR/collector-user.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} UNIX Collector Platform"
echo $PLATFORM > $OUTPUT_DIR/platform.txt

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

echo "  ${COL_ENTRY}>${RESET} SSH settings"
sshd -T 1> $OUTPUT_DIR/general/sshd-t.txt 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Release"
uname -r 1> $OUTPUT_DIR/general/release.txt 2> /dev/null
cp /etc/*release /etc/debian_version $OUTPUT_DIR/general/ 2> /dev/null

if [ $PLATFORM != "aix" ]
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

echo "  ${COL_ENTRY}>${RESET} Process list"
ps -efl 1> $OUTPUT_DIR/general/ps.txt 2> /dev/null
ps -auxww 1> $OUTPUT_DIR/general/ps-auxww 2> /dev/null
ps -deaf 1> $OUTPUT_DIR/general/ps-deaf 2> /dev/null
ps -aux 1> $OUTPUT_DIR/general/ps-aux 2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Cron scheduler"
if [ -f "/etc/crontab" ] && [ -r "/etc/crontab" ]; then
	cp /etc/crontab $OUTPUT_DIR/general/etc-crontab.txt 2>/dev/null
fi

mkdir $OUTPUT_DIR/general/crontabs/
if [ $PLATFORM = "mac" ]
then
    crontab -v 1> $OUTPUT_DIR/general/crontab-v.txt 2> /dev/null
	crontab -l 1> $OUTPUT_DIR/general/crontab-l.txt 2> /dev/null
	cp -R /var/at/ $OUTPUT_DIR/general/crontabs/
	cp -R /Library/StartupItems/ $OUTPUT_DIR/general/crontabs/StartupItems
	cp -R /System/Library/StartupItems/ $OUTPUT_DIR/general/crontabs/System_StartupItems
	cp -R /Library/LaunchAgents/ $OUTPUT_DIR/general/crontabs/LaunchAgents
	cp -R /System/Library/LaunchAgents/ $OUTPUT_DIR/general/crontabs/System_LaunchAgents
	cp -R /usr/lib/cron/jobs/ $OUTPUT_DIR/general/crontabs/usr_lib_cron_jobs
	cp -R /usr/lib/cron/tabs/ $OUTPUT_DIR/general/crontabs/usr_lib_cron_tabs
	cp /etc/periodic.conf $OUTPUT_DIR/general/crontabs/
	cp /etc/periodic.conf.local $OUTPUT_DIR/general/crontabs/
	cp -R /etc/periodic/ $OUTPUT_DIR/general/crontabs/
	cp -R /etc/daily.local/ $OUTPUT_DIR/general/crontabs/
	cp -R /etc/weekly.local/ $OUTPUT_DIR/general/crontabs/
	cp -R /etc/monthly.local/ $OUTPUT_DIR/general/crontabs/
	cp -R /etc/periodic/daily/ $OUTPUT_DIR/general/crontabs/periodic_daily
	cp -R /etc/periodic/weekly/ $OUTPUT_DIR/general/crontabs/periodic_weekly
	cp -R /etc/periodic/monthly/ $OUTPUT_DIR/general/crontabs/periodic_monthly
	cp -R /usr/local/etc/periodic/ $OUTPUT_DIR/general/crontabs/usr_local_etc_periodic
	cp -R /etc/crontab $OUTPUT_DIR/general/crontabs/etc_crontab
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
	cat /var/spool/cron/crontabs/$name | grep -v "^#" | while read null null null null null name null
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
        if [ -f $name ]
        then
	    ls -lL /etc/cron.d/$name 1>> $OUTPUT_DIR/general/cron.d/perms 2> /dev/null
            cp /etc/cron.d/$name $OUTPUT_DIR/general/cron.d/$name 2> /dev/null
	    if [ $PLATFORM = "linux" ]
	    then
		cat /etc/cron.d/$name | grep -v "^#" | while read null null null null null user name null
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
        if [ -f $name ]
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
        if [ -f $name ]
        then
	    ls -lL /etc/cron.daily/$name $OUTPUT_DIR/general/cron.daily/perms 2> /dev/null
            cp /etc/cron.daily/$name $OUTPUT_DIR/general/cron.daily/$name 2> /dev/null
        fi
    done
fi
if [ -d /etc/cron.weekly ]
then
    mkdir $OUTPUT_DIR/general/cron.weekly 2> /dev/null
    for name in `ls /etc/cron.weekly/`
    do
        if [ -f $name ]
        then
	    ls -lL /etc/cron.weekly/$name $OUTPUT_DIR/general/cron.weekly/perms 2> /dev/null
            cp /etc/cron.weekly/$name $OUTPUT_DIR/general/cron.weekly/$name 2> /dev/null
        fi
    done
fi
if [ -d /etc/cron.monthly ]
then
    mkdir $OUTPUT_DIR/general/cron.monthly 2> /dev/null
    for name in `ls /etc/cron.monthly/`
    do
        if [ -f $name ]
        then
	    ls -lL /etc/cron.monthly/$name $OUTPUT_DIR/general/cron.monthly/perms 2> /dev/null
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
elif [ $PLATFORM = "mac" ]
then
	kmutil showloaded 1> $OUTPUT_DIR/general/kernel-modules.txt 2> /dev/null
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
    zoneadm list 1> $OUTPUT_DIR/general/zones.txt 2> /dev/null
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
    pkginfo -x 2> /dev/null | awk '{ if ( NR % 2 ) { prev = $1 } else { print prev" "$0 } }' > $OUTPUT_DIR/software/nopc-solaris-pkginfo.txt 2> /dev/null
    showrev -a > $OUTPUT_DIR/software/nopc-showrev.txt 2> /dev/null
elif [ $PLATFORM = "aix" ]
then
    lslpp -L all 1> $OUTPUT_DIR/software/software-lslpp.txt 2> /dev/null
    lslpp -Lc 1> $OUTPUT_DIR/software/nopc-aix-patchlist.txt 2> /dev/null
    pkginfo 1> $OUTPUT_DIR/software/software-pkginfo.txt 2> /dev/null
elif [ $PLATFORM = "mac" ]
then
    find / -iname "*.app" 1> $OUTPUT_DIR/software/software-apps.txt 2> /dev/null
	find / -iname "*.plist" 1> $OUTPUT_DIR/software/software-plist.txt 2> /dev/null
    ls -la /Applications/ 1> $OUTPUT_DIR/software/software-Applications-folder.txt 2> /dev/null
	cp -R /System/Library/Extensions/ 1> $OUTPUT_DIR/software/System_Kernel_Extensions 2> /dev/null
	cp -R /Library/Extensions/ 1> $$OUTPUT_DIR/software/Library_Kernel_Extensions 2> /dev/null
elif [ $PLATFORM = "hpux" ]
then
    swlist 1> $OUTPUT_DIR/software/software-swlist.txt 2> /dev/null
    swlist -l fileset -a revision 1> $OUTPUT_DIR/software/nopc-hpux-patchlist.txt 2> /dev/null
else
    cp /etc/redhat-release $OUTPUT_DIR/software/ 2> /dev/null
    rpm -q -a 1> $OUTPUT_DIR/software/software-rpm.txt 2> /dev/null
    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n' > $OUTPUT_DIR/software/nopc-rpm-patchlist.txt 2> /dev/null
    dpkg --list 1> $OUTPUT_DIR/software/software-dpkg.txt 2> /dev/null
    dpkg -l 1> $OUTPUT_DIR/software/nopc-dpkg-patchlist.txt 2> /dev/null
    ls -1 /var/log/packages 1> $OUTPUT_DIR/software/nopc-slackware-patchlist.txt 2> /dev/null
    grep -A 1 displayName /Library/Receipts/InstallHistory.plist 2>/dev/null| grep string | sed 's/<string>\(.*\)<\/string>.*/\1/g'  | sed 's/^[      ]*//g'|tr  -d -c 'a-zA-Z0-9\n _-'|sort|uniq > $OUTPUT_DIR/software/nopc-osx-patchlist.txt 2> /dev/null
    ls -1 /Library/Receipts/boms /private/var/db/receipts 2>/dev/null | grep '\.bom$' > $OUTPUT_DIR/software/nopc-osx-bomlist.txt 2> /dev/null
    emerge -pev world 1> $OUTPUT_DIR/software/software-emerge.txt 2> /dev/null
    pkg_info > $OUTPUT_DIR/software/nopc-freebsd-patchlist.txt 2> /dev/null
    chkconfig --list $OUTPUT_DIR/software/chkconfig--list.txt 2> /dev/null
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

echo "  ${COL_ENTRY}>${RESET} Compiler tools"
find / \( -name gcc* -o -name javac -o -name perl* -o -name tclsh* -o -name python* -o -name ruby* \) -ls 1> $OUTPUT_DIR/software/compiler.txt 2> /dev/null


# ------------------------------------
# PART 5: LOG FILES, HOME DIR and PROC folders
# ------------------------------------

echo "${COL_SECTION}LOG, HOME and PROC FILE COLLECTION [50% ]:${RESET}"
mkdir $OUTPUT_DIR/logs

echo "  ${COL_ENTRY}>${RESET} Copying logs"

if [ $PLATFORM = "solaris" ]
then
    cp -R /var/adm/ $OUTPUT_DIR/logs/
	cp -R /var/log/ $OUTPUT_DIR/logs/
elif [ $PLATFORM = "aix" ]
then
    cp -R /var/adm/ $OUTPUT_DIR/logs/
elif [ $PLATFORM = "mac" ]
then
    cp -R /private/var/log $OUTPUT_DIR/logs/private_var_log
	cp -R /private/var/logs $OUTPUT_DIR/logs/private_var_logs
	cp -R /var/log $OUTPUT_DIR/logs/var_log
	cp -R /Library/Logs $OUTPUT_DIR/logs/library_logs
elif [ $PLATFORM = "linux" ]
then
    cp -R /var/log/ $OUTPUT_DIR/logs/
elif [ $PLATFORM = "generic" ]
then
    cp -R /var/log/ $OUTPUT_DIR/logs/
elif [ $PLATFORM = "hpux" ]
then
    cp -R /var/log/ $OUTPUT_DIR/logs/
fi

mkdir $OUTPUT_DIR/homedir
echo "  ${COL_ENTRY}>${RESET} Copying home dirs"

if [ $PLATFORM = "solaris" ]
then
    cp -R /home/ $OUTPUT_DIR/homedir/
	cp -R /root/ $OUTPUT_DIR/homedir/
	cp -R /export/home/ $OUTPUT_DIR/homedir/home-export
elif [ $PLATFORM = "aix" ]
then
    cp -R /home/ $OUTPUT_DIR/homedir/
	cp -R /root/ $OUTPUT_DIR/homedir/
elif [ $PLATFORM = "mac" ]
then
	cp -R /Users/ $OUTPUT_DIR/homedir/
	cp -R /home/ $OUTPUT_DIR/homedir/
elif [ $PLATFORM = "linux" ]
then
    cp -R /home/ $OUTPUT_DIR/homedir/
	cp -R /root/ $OUTPUT_DIR/homedir/
elif [ $PLATFORM = "generic" ]
then
    cp -R /home/ $OUTPUT_DIR/homedir/
	cp -R /root/ $OUTPUT_DIR/homedir/
elif [ $PLATFORM = "hpux" ]
then
    cp -R /home/ $OUTPUT_DIR/homedir/
	cp -R /root/ $OUTPUT_DIR/homedir/
fi

mkdir $OUTPUT_DIR/procfiles
echo "  ${COL_ENTRY}>${RESET} Copying proc dirs"

if [ $PLATFORM = "solaris" ]
then
    cp -R /proc/ $OUTPUT_DIR/procfiles/
elif [ $PLATFORM = "aix" ]
then
    cp -R /proc/ $OUTPUT_DIR/procfiles/
elif [ $PLATFORM = "linux" ]
then
    cp -R /proc/ $OUTPUT_DIR/procfiles/
elif [ $PLATFORM = "generic" ]
then
    cp -R /proc/ $OUTPUT_DIR/procfiles/
elif [ $PLATFORM = "hpux" ]
then
    cp -R /home/ $OUTPUT_DIR/procfiles/
fi

if [ $PLATFORM = "mac" ]
then
	echo "${COL_SECTION} Copying plist files"
	mkdir $OUTPUT_DIR/plist
	find / -type f -iname "*.plist" 2>/dev/null | while read line
	mkdir -p "$OUTPUT_DIR/plist`dirname $line`"
	cp -p "$line" "$OUTPUT_DIR/plist`dirname $line`"
fi

# ------------------------------------
# PART 6: SUID
# ------------------------------------

echo "${COL_SECTION}SUID/SGID SEARCH [60% ]:${RESET}"
mkdir $OUTPUT_DIR/setuid
echo "  ${COL_ENTRY}>${RESET} Finding all SUID/SGID binaries"
find / -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null | while read line
do
	mkdir -p "$OUTPUT_DIR/setuid`dirname $line`"
	cp -p "$line" "$OUTPUT_DIR/setuid`dirname $line`"
done


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
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	fi
elif [ $PLATFORM = "solaris" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec digest -a sha256 -v {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec csum -h MD5 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	fi	
elif [ $PLATFORM = "mac" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-sgid_suid
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-sgid_suid
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec shasum -a 256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-sgid_suid
		done	
	fi	
fi

echo "  ${COL_ENTRY}>${RESET} Hashing all HOME dirs"
if [ $PLATFORM = "linux" ]
then 
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	fi
elif [ $PLATFORM = "solaris" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find /home/ /root/ -type f -exec digest -a sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find /home/ /root/ -type f -exec csum -h MD5 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /home/ /root/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /home/ /root/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /home/ /root/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /home/ /root/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	fi	
elif [ $PLATFORM = "mac" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /Users/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /Users/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-homedir
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /Users/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-homedir
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /Users/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find /Users/ -type f -exec shasum -a 256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-homedir
		done	
	fi	
fi

echo "  ${COL_ENTRY}>${RESET} Hashing all /bin/* /sbin/* /usr/* /opt/* /tmp/* dirs"
if [ $PLATFORM = "linux" ]
then 
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	fi
elif [ $PLATFORM = "generic" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done
    fi		
elif [ $PLATFORM = "solaris" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins
		done	
	elif [ -x "$(command -v digest)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec digest -a sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	fi
elif [ $PLATFORM = "aix" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins
		done	
	elif [ -x "$(command -v csum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec csum -h MD5 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/shaMD5sum-variousbins
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	fi
elif [ $PLATFORM = "hpux" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /tmp/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	fi
elif [ $PLATFORM = "mac" ]
then
    if [ -x "$(command -v sha256sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -type f -exec sha256sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	elif [ -x "$(command -v sha1sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -type f -exec sha1sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha1sum-variousbins
		done	
	elif [ -x "$(command -v md5sum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -type f -exec md5sum {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/md5sum-variousbins
		done	
	elif [ -x "$(command -v openssl)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -type f -exec openssl dgst -sha256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
		done	
	elif [ -x "$(command -v shasum)" ]
	then
		find /bin/ /sbin/ /usr/ /opt/ /Library/ /tmp/ /System/ -type f -exec shasum -a 256 {} \; 2>/dev/null | while read line
		do
		  echo $line >> $OUTPUT_DIR/hashes/sha256sum-variousbins
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

echo "  ${COL_ENTRY}>${RESET} Netstat"
netstat -an 1> $OUTPUT_DIR/network/netstat-an.txt 2> /dev/null

if [ $PLATFORM != "solaris" ]
then
	netstat -anp 1> $OUTPUT_DIR/network/netstat-apn.txt 2> /dev/null
fi

echo "  ${COL_ENTRY}>${RESET} ARP cache"
arp -a 1> $OUTPUT_DIR/network/arp.txt 2> /dev/null

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

if [ -x /sbin/iptables ]
then
    echo "  ${COL_ENTRY}>${RESET} IP Tables"
    iptables -L -v -n 1> $OUTPUT_DIR/network/iptables.txt 2> /dev/null
fi

if [ -x /sbin/ip6tables ]
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


# --------------------------------
# PART 9: CLEANUP / CREATE ARCHIVE
# --------------------------------

echo "${COL_SECTION}FINISHING [100%]:${RESET}"

echo "  ${COL_ENTRY}>${RESET} Removing empty files"
for REMOVELIST in `find $OUTPUT_DIR -size 0`
do
    rm -rf $REMOVELIST 2> /dev/null
done

echo "  ${COL_ENTRY}>${RESET} Creating TAR file"
tar zcf $TAR_FILE $OUTPUT_DIR.gz 1> /dev/null  2> /dev/null || tar cf $TAR_FILE $OUTPUT_DIR 1> /dev/null  2> /dev/null

echo "  ${COL_ENTRY}>${RESET} Removing temporary directory"
rm -rf $OUTPUT_DIR

echo ""
echo "Finished! Copy the audit file ${TAR_FILE} to a safe location"
echo "${RESET}"

exit 0
