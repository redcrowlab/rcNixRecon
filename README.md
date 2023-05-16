# rcNixRecon

#######################################################################

Red Crow Labs 

#######################################################################

DESCRIPTION: 
rcNixRecon is PoC Code to conduct a survey of a Unix based host and attempt to collect basic information useful to an attacker or for identifying potential vulnerabilities and defenses. 

Why a shell script? This code is designed to be as portable as possible so that it can work on devices from desktops to super computers to IoT running embedded Linux. Not all systems, especially embedded or IoT have python, perl, etc. available.

This tool performs the following checks:

- Collects general system info such as OC, update, who is logged in, etc.
- Collects Disk and network mount info.
- Collects information about memory and CPU.
- Searches for SUID root binaries.
- Lists local users and groups.
- Lists all running processes.
- Lists listening ports and user / process name when possible.
- Displays the password hashes if run as root.
- Checks to see if a firewall is running and displays the rules.
- Checks for running containers like docker or kubernetes.
- Searches the process table for a list of processes such as AV, SEIM, IDS, DLP, etc.
- Has the ability to collect recursive file permissions under a specified directory.


========================================================================= INSTALL:

INSTALLATION:

git clone https://github.com/redcrowlab/rcNixRecon.git

========================================================================= USAGE:
USAGE:

chmod 755 rcNixRecon.sh
/bin/sh rcNixRecon.sh

========================================================================= 

NOTE:

The tool will give different results depending on if it is run as root or as a regular user.
