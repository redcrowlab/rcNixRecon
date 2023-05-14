#!/bin/sh

#####################################################################
# rcNixRecon.sh - Gathers useful information about a system
# including users, groups, encrypted hashes, running processes, etc.
# 

#####################################################################
# Check if running as root
isRootUser() {
        if [ "$(id -u)" -eq 0 ]; then
                # User is root
                return 0
        else
                # User is not root
                return 1
        fi
}


#####################################################################
# Gather General Host Information
collectSystemInfo() {
        echo "Output of 'id':"
        id

        echo "Output of 'last':"
        last

        echo "Output of 'who':"
        who

        echo "Output of 'uptime':"
        uptime

        echo "Output of 'uname -a':"
        uname -a

        if [ -f "/etc/lsb-release" ]; then
                echo "Output of 'cat /etc/lsb-release':"
                cat /etc/lsb-release
        else
                #echo "Unable to find '/etc/lsb-release'."
                echo ""
        fi
}


#####################################################################
# Collect disk informatioon
collectDiskInfo() {
    echo "Local Disk Information:"
    echo "-----------------------"
    df -h

    echo ""
    echo "Partition Information:"
    echo "-----------------------"
    lsblk

    echo ""
    echo "Network Mounts:"
    echo "-----------------------"
    mount | awk '$1 ~ /^\/\/[[:alnum:]]/ {print}'
}


#####################################################################
# Get system stat info about CPU and Memory
getSystemStats() {
    # Memory information
    total_memory=$(free -h --si | awk '/^Mem:/{print $2}')
    used_memory=$(free -h --si | awk '/^Mem:/{print $3}')
    free_memory=$(free -h --si | awk '/^Mem:/{print $4}')
    memory_percentage=$(free | awk '/^Mem:/{print ($3/$2) * 100}')

    # CPU information
    cpu_usage=$(top -bn1 | awk '/^%Cpu/{print $2}')
    cpu_cores=$(nproc)

    # Output information
    echo "Memory Information:"
    echo "------------------"
    echo "Total memory: $total_memory"
    echo "Used memory: $used_memory"
    echo "Free memory: $free_memory"
    echo "Memory usage: $memory_percentage%"

    echo

    echo "CPU Information:"
    echo "---------------"
    echo "CPU usage: $cpu_usage%"
    echo "Number of CPU cores: $cpu_cores"
}


#####################################################################
# Find SUID Root Binaries
searchSUIDRootBinaries() {
    suid_files=$(find / -perm -4000 -user root -type f 2>/dev/null)

    if [ -n "$suid_files" ]; then
        echo "SUID root binaries:"
        echo "-------------------"
        echo "$suid_files"
    else
        echo "No SUID root binaries found"
    fi
}


#####################################################################
# List local users
listLocalUsers() {
        if command -v getent >/dev/null; then
                # Using getent command if available (portable across different Unix systems)
                getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }'
        else
                # Fallback for systems without getent (may not work on all systems)
                awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/passwd
        fi
}


#####################################################################
# List groups and group membership
listGroupsAndMembership() {
        if command -v getent >/dev/null; then
                # Using getent command if available (portable across different Unix systems)
                getent group | awk -F: '{ printf "%s: %s\n", $1, $4 }' | sed 's/,/,\ /g'
        else
                # Fallback for systems without getent (may not work on all systems)
                awk -F: '{ printf "%s: %s\n", $1, $4 }' /etc/group | sed 's/,/,\ /g'
        fi

}


#####################################################################
# List running processes
listRunningProcesses() {
        if command -v ps >/dev/null; then
                # Using ps command if available (portable across different Unix systems)
                ps -e -o pid,cmd,user
        else
                # Fallback for systems without ps (may not work on all systems)
                if command -v procfs >/dev/null; then
                        # Using procfs if available (common on Linux)
                        procfs=/proc
                        ls $procfs | grep -E '^[0-9]+$' | xargs -I {} sh -c "printf '{} '; cat $procfs/{}/cmdline; echo"
                else
                        echo "Unable to list running processes. Missing required commands."
                fi
        fi
}


#####################################################################
# List listening ports
listListeningPorts() {
        if command -v ss >/dev/null; then
                # Using ss command if available (portable across different Unix systems)
                ss -tunlp
        elif command -v netstat >/dev/null; then
                # Fallback for systems without ss command, using netstat instead
                netstat -tunlp
        else
                echo "Unable to list listening ports. Missing required commands."
                return 1
        fi
}


#####################################################################
# If running as root, show shadow file
displayShadow() {
        if isRootUser; then
                cat /etc/shadow
        else
                echo "CANT LIST HASHES, NOT RUNNING AS ROOT"
        fi
}



#####################################################################
# Check if firewall is running and output rules
checkFirewall() {
    if isRootUser; then
        # Check if iptables is installed
        if command -v iptables >/dev/null; then
            echo "iptables Firewall Rules:"
            echo "------------------------"
            iptables -L
            echo
        fi

        # Check if UFW is installed and active
        if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
            echo "UFW Firewall Rules:"
            echo "-------------------"
            ufw status verbose
            echo
        fi

        # Check if firewalld is installed and active
        if command -v firewalld >/dev/null && systemctl is-active --quiet firewalld; then
            echo "firewalld Firewall Rules:"
            echo "--------------------------"
            firewall-cmd --list-all
            echo
        fi

        # If no firewall is detected
        if ! command -v iptables >/dev/null && ! command -v ufw >/dev/null && ! command -v firewalld >/dev/null; then
            echo "No firewall is currently installed."
        fi
    else
        echo "CANT CHECK FIREWALL, NOT RUNNING AS ROOT"
    fi
}


#####################################################################
# Search the process table for a list of processes
searchProcesses() {
    found=0    # Flag to track if any processes are found

    # Iterate over the search strings
    for string in "$@"; do
        count=$(pgrep -c -f "$string")    # Count the number of processes matching the string

        # If at least one process is found, display the result
        if [ "$count" -gt 0 ]; then
            echo "$string detected"
            found=1
        fi
    done

    # If no processes are found, display the appropriate message
    if [ "$found" -eq 0 ]; then
        echo "No processes detected"
    fi
}


#####################################################################
# Search the process table for a list of processes
checkContainers() {
    found=0  # Flag to track if any containers are found

    # Check if Docker is running
    if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
        echo "Docker is running"
        found=1
    fi

    # Check if Podman is running
    if command -v podman >/dev/null && podman info >/dev/null 2>&1; then
        echo "Podman is running"
        found=1
    fi

    # Check if Kubernetes is running
    if command -v kubectl >/dev/null && kubectl cluster-info >/dev/null 2>&1; then
        echo "Kubernetes is running"
        found=1
    fi

    # Check if Containerd is running
    if command -v containerd >/dev/null && containerd --version >/dev/null 2>&1; then
        echo "Containerd is running"
        found=1
    fi

    # Check if CRI-O is running
    if command -v crictl >/dev/null && crictl info >/dev/null 2>&1; then
        echo "CRI-O is running"
        found=1
    fi

    # Check if LXC is running
    if command -v lxc-start >/dev/null && lxc-ls >/dev/null 2>&1; then
        echo "LXC is running"
        found=1
    fi

    # Check if rkt is running
    if command -v rkt >/dev/null && rkt version >/dev/null 2>&1; then
        echo "rkt is running"
        found=1
    fi

    # Check if OpenVZ is running
    if command -v vzlist >/dev/null && vzlist -a >/dev/null 2>&1; then
        echo "OpenVZ is running"
        found=1
    fi

    # Check if Singularity is running
    if command -v singularity >/dev/null && singularity --version >/dev/null 2>&1; then
        echo "Singularity is running"
        found=1
    fi

    # If no containers are detected, display the appropriate message
    if [ "$found" -eq 0 ]; then
        echo "No containers are currently running"
    fi
}


#####################################################################
# Collects file permissions recursively on a given directory
collectFilePermissions() {
    directory=$1

    # Check if the directory exists
    if [ -d "$directory" ]; then
        # Collect file permissions recursively
        permissions=$(find "$directory" -printf "%m %p\n" 2>/dev/null)

        if [ -n "$permissions" ]; then
            echo "File Permissions in $directory:"
            echo "-------------------------------"
            echo "$permissions"
        else
            echo "No files or directories found in $directory"
        fi
    else
        echo "Directory $directory does not exist"
    fi
}


#####################################################################
# MAIN
echo "==============================================================="
echo "RUNNING PRIVILEGE CHECK"
echo "==============================================================="
if isRootUser; then
        echo "Running as root"
else
        echo "Running without privileges"
fi

echo "\n"

echo "==============================================================="
echo "GENERAL HOST INFORMATION"
echo "==============================================================="
collectSystemInfo

echo "\n"

echo "==============================================================="
echo "DISK AND STORAGE INFORMATION"
echo "==============================================================="
collectDiskInfo

echo "\n"

echo "==============================================================="
echo "MEMORY AND CPU INFORMATION"
echo "==============================================================="
getSystemStats

echo "\n"

echo "==============================================================="
echo "LIST SUID ROOT BINARIES"
echo "==============================================================="
searchSUIDRootBinaries

echo "\n"

echo "==============================================================="
echo "LIST USERS"
echo "==============================================================="
listLocalUsers

echo "\n"

echo "==============================================================="
echo "LIST GROUPS"
echo "==============================================================="
listGroupsAndMembership

echo "\n"

echo "==============================================================="
echo "LIST RUNNING PROCESSES"
echo "==============================================================="
listRunningProcesses

echo "\n"

echo "==============================================================="
echo "LIST LISTENING PORTS"
echo "==============================================================="
listListeningPorts

echo "\n"

echo "==============================================================="
echo "PASSWORD HASHES"
echo "==============================================================="
displayShadow

echo "\n"

echo "==============================================================="
echo "FIREWALL RULESS"
echo "==============================================================="
checkFirewall

echo "\n"

echo "==============================================================="
echo "RUNNING ANTIVIRUS PROCESSES"
echo "==============================================================="
searchProcesses "clamd" "sav-protect" "esets_daemon" "bdscan" "avast" "f-prot" "cmdavd" "mcd" "ds_agent" "avp"

echo "\n"

echo "==============================================================="
echo "RUNNING SEIM PROCESSES"
echo "==============================================================="
searchProcesses "ossec" "wazuh-agent" "splunkd" "filebeat" "packetbeat" "auditbeat" "mfeesp" "lmagent" "dsmc"

echo "\n"

echo "==============================================================="
echo "RUNNING EDR PROCESSES"
echo "==============================================================="
searchProcesses "falcon-sensor" "cbdefense-sensor" "cylance-agent" "sentinel-agent" "mfetpd" "rtvscan" "smc" "mephisto" "sophos" "sav" "vstskmgr"

echo "\n"

echo "==============================================================="
echo "FILE INTEGRITY MONITORING PROCESSES"
echo "==============================================================="
searchProcesses "aid" "tripwire" "verisys" "verisysd" "verisys-agent"

echo "\n"

echo "==============================================================="
echo "FILE INTEGRITY MONITORING PROCESSES"
echo "==============================================================="
searchProcesses "aid" "tripwire" "verisys" "verisysd" "verisys-agent"

echo "\n"

echo "==============================================================="
echo "DLP PROCESSES"
echo "==============================================================="
searchProcesses "VontuMonitor" "VontuEnforce" "VontuManager" "dlpagent" "dlpmanager" "dlpserver" "TridentDLP" "DataSecurityService" "DGAgent" "DGServer"

echo "\n"

echo "==============================================================="
echo "CHECK FOR CONTAINERS"
echo "==============================================================="
checkContainers
