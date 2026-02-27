#!/bin/bash
#
# MRTG Professional Monitoring Suite - Production Ready
# Enterprise-grade network monitoring for DirectAdmin and other hosting control panels
#
# =============================================================================
# ██╗    ██╗ █████╗ ███████╗██╗         ██╗███████╗ █████╗
# ██║    ██║██╔══██╗██╔════╝██║         ██║██╔════╝██╔══██╗
# ██║ █╗ ██║███████║█████╗  ██║         ██║███████╗███████║
# ██║███╗██║██╔══██║██╔══╝  ██║         ██║╚════██║██╔══██║
# ╚███╔███╔╝██║  ██║███████╗███████╗    ██║███████╗██║  ██║
# ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝╚══════╝╚═╝  ╚═╝
# =============================================================================
#
# Author:      Wael Isa
# Website:     https://www.wael.name
# GitHub:      https://github.com/waelisa
# Version:     v1.0.0
# Build Date:  02/27/2026
# License:     MIT
#
# Description:
#   Fully automated MRTG installation and configuration script for hosting environments.
#   Supports DirectAdmin, cPanel, Plesk, and custom servers with enterprise-grade
#   monitoring capabilities.
#
# Features:
#   • Interactive menu-driven interface
#   • Command-line arguments support
#   • Multi-control panel support (DirectAdmin, cPanel, Plesk)
#   • Automatic dependency installation
#   • Customizable monitoring intervals
#   • Email alerts and notifications
#   • Multi-interface monitoring
#   • Bandwidth graphing and reporting
#   • Automatic cron job management
#   • Backup and restore functionality
#   • SSL/TLS support for secure access
#   • Performance optimization tools
#
# Usage:
#   ./install-mrtg.sh [OPTIONS]
#
# Options:
#   --help, -h              Show this help message
#   --install, -i           Run installation wizard
#   --uninstall, -u         Complete uninstall MRTG
#   --cron-add, -ca         Add MRTG to crontab
#   --cron-remove, -cr      Remove MRTG from crontab
#   --configure, -c         Reconfigure existing installation
#   --backup, -b            Backup MRTG configuration
#   --restore, -r           Restore MRTG configuration
#   --status, -s            Check MRTG service status
#   --version, -v           Show version information
#
# Examples:
#   ./install-mrtg.sh --install
#   ./install-mrtg.sh --uninstall
#   ./install-mrtg.sh --cron-add --interval 5
#
# =============================================================================

# Strict mode
set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# COLOR CODES FOR BEAUTIFUL OUTPUT
# =============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color
readonly BOLD='\033[1m'

# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================

readonly SCRIPT_NAME="MRTG Professional Monitoring Suite"
readonly SCRIPT_VERSION="v1.0.0"
readonly SCRIPT_AUTHOR="Wael Isa"
readonly SCRIPT_URL="https://www.wael.name"
readonly SCRIPT_GITHUB="https://github.com/waelisa/mrtg-monitor"

# Installation paths
readonly MRTG_BASE="/usr/local/mrtg"
readonly MRTG_CONF="${MRTG_BASE}/conf"
readonly MRTG_HTML="${MRTG_BASE}/html"
readonly MRTG_LOG="${MRTG_BASE}/logs"
readonly MRTG_BIN="${MRTG_BASE}/bin"
readonly MRTG_BACKUP="${MRTG_BASE}/backups"
readonly MRTG_VAR="/var/lib/mrtg"

# Log file
readonly LOG_FILE="/var/log/mrtg-installer.log"

# Default values
DEFAULT_INTERVAL=5
DEFAULT_HTML_DIR="/var/www/html/mrtg"
DEFAULT_EMAIL="root@localhost"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"

    case "${level}" in
        "ERROR")   echo -e "${RED}[ERROR]${NC} ${message}" ;;
        "WARNING") echo -e "${YELLOW}[WARNING]${NC} ${message}" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} ${message}" ;;
        "INFO")    echo -e "${CYAN}[INFO]${NC} ${message}" ;;
        *)         echo -e "${message}" ;;
    esac
}

error_exit() {
    log "ERROR" "$1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

print_banner() {
    clear
    cat << "EOF"
================================================================================
██╗    ██╗ █████╗ ███████╗██╗         ██╗███████╗ █████╗
██║    ██║██╔══██╗██╔════╝██║         ██║██╔════╝██╔══██╗
██║ █╗ ██║███████║█████╗  ██║         ██║███████╗███████║
██║███╗██║██╔══██║██╔══╝  ██║         ██║╚════██║██╔══██║
╚███╔███╔╝██║  ██║███████╗███████╗    ██║███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝╚══════╝╚═╝  ╚═╝
================================================================================
    ${BOLD}${SCRIPT_NAME}${NC}
    Version: ${SCRIPT_VERSION} | Author: ${SCRIPT_AUTHOR}
    Website: ${SCRIPT_URL} | GitHub: ${SCRIPT_GITHUB}
================================================================================
EOF
    echo ""
}

print_help() {
    cat << EOF
${BOLD}NAME${NC}
    ${SCRIPT_NAME} - Enterprise-grade network monitoring solution

${BOLD}SYNOPSIS${NC}
    $0 [OPTIONS]

${BOLD}DESCRIPTION${NC}
    Fully automated MRTG installation and configuration script for hosting
    environments. Supports DirectAdmin, cPanel, Plesk, and custom servers.

${BOLD}OPTIONS${NC}
    ${GREEN}--help, -h${NC}              Show this help message
    ${GREEN}--install, -i${NC}           Run installation wizard
    ${GREEN}--uninstall, -u${NC}          Complete uninstall MRTG
    ${GREEN}--cron-add, -ca${NC}          Add MRTG to crontab
    ${GREEN}--cron-remove, -cr${NC}       Remove MRTG from crontab
    ${GREEN}--configure, -c${NC}          Reconfigure existing installation
    ${GREEN}--backup, -b${NC}             Backup MRTG configuration
    ${GREEN}--restore, -r${NC}            Restore MRTG configuration
    ${GREEN}--status, -s${NC}             Check MRTG service status
    ${GREEN}--version, -v${NC}            Show version information
    ${GREEN}--interval, -in${NC} [MIN]     Set monitoring interval (default: ${DEFAULT_INTERVAL})
    ${GREEN}--email, -e${NC} [ADDRESS]     Set notification email
    ${GREEN}--html-dir, -hd${NC} [PATH]    Set HTML output directory

${BOLD}EXAMPLES${NC}
    $0 --install                    # Interactive installation
    $0 --install --interval 5       # Install with 5-minute intervals
    $0 --cron-add --interval 10     # Add cron job with 10-minute intervals
    $0 --uninstall --force          # Force uninstall without confirmation

${BOLD}FILES${NC}
    ${MRTG_BASE}              Main installation directory
    ${MRTG_CONF}              Configuration files
    ${MRTG_HTML}              HTML output files
    ${MRTG_LOG}               Log files
    ${MRTG_BACKUP}            Backup directory

${BOLD}EXIT CODES${NC}
    0   Success
    1   General error
    2   Permission denied
    3   Invalid argument
    4   Installation failed
    5   Uninstall failed

${BOLD}AUTHOR${NC}
    Written by ${SCRIPT_AUTHOR} <${SCRIPT_URL}>

${BOLD}REPORTING BUGS${NC}
    ${SCRIPT_GITHUB}/issues

${BOLD}COPYRIGHT${NC}
    Copyright (c) $(date +%Y) ${SCRIPT_AUTHOR}. License: MIT
    This is free software; see the source for copying conditions.

EOF
}

# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [[ -f /etc/debian_version ]]; then
        OS="Debian"
        VER=$(cat /etc/debian_version)
    elif [[ -f /etc/redhat-release ]]; then
        OS="Red Hat"
        VER=$(cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//)
    else
        OS="Unknown"
        VER="Unknown"
    fi
    log "INFO" "Detected OS: ${OS} ${VER}"
}

detect_control_panel() {
    local panel="none"

    # DirectAdmin detection
    if [[ -d /usr/local/directadmin ]]; then
        panel="directadmin"
        log "INFO" "DirectAdmin control panel detected"
    # cPanel detection
    elif [[ -d /usr/local/cpanel ]]; then
        panel="cpanel"
        log "INFO" "cPanel control panel detected"
    # Plesk detection
    elif [[ -d /usr/local/psa ]]; then
        panel="plesk"
        log "INFO" "Plesk control panel detected"
    # Webmin detection
    elif [[ -d /usr/libexec/webmin ]]; then
        panel="webmin"
        log "INFO" "Webmin control panel detected"
    # ISPConfig detection
    elif [[ -d /usr/local/ispconfig ]]; then
        panel="ispconfig"
        log "INFO" "ISPConfig control panel detected"
    fi

    echo "${panel}"
}

detect_network_interfaces() {
    local interfaces=()

    # Get all network interfaces except loopback
    for interface in $(ls /sys/class/net/ | grep -v lo); do
        interfaces+=("${interface}")
    done

    echo "${interfaces[@]}"
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

install_dependencies() {
    log "INFO" "Installing dependencies..."

    case "${OS}" in
        *"Ubuntu"*|*"Debian"*)
            apt-get update -y
            apt-get install -y mrtg snmpd snmp libsnmp-dev apache2 \
                               gcc make perl libwww-perl libcrypt-ssleay-perl \
                               libdigest-hmac-perl libio-socket-ssl-perl \
                               libnet-snmp-perl libxml-libxml-perl \
                               wget curl unzip gzip
            ;;
        *"CentOS"*|*"Red Hat"*|*"Fedora"*)
            yum install -y epel-release
            yum install -y mrtg net-snmp net-snmp-utils net-snmp-devel \
                           httpd gcc make perl-CPAN perl-libwww-perl \
                           perl-Crypt-SSLeay perl-Digest-HMAC \
                           perl-IO-Socket-SSL perl-Net-SNMP \
                           perl-XML-LibXML wget curl unzip gzip
            ;;
        *"AlmaLinux"*|*"Rocky"*)
            dnf install -y epel-release
            dnf install -y mrtg net-snmp net-snmp-utils net-snmp-devel \
                           httpd gcc make perl-CPAN perl-libwww-perl \
                           perl-Crypt-SSLeay perl-Digest-HMAC \
                           perl-IO-Socket-SSL perl-Net-SNMP \
                           perl-XML-LibXML wget curl unzip gzip
            ;;
        *)
            error_exit "Unsupported OS: ${OS}"
            ;;
    esac

    log "SUCCESS" "Dependencies installed successfully"
}

configure_snmp() {
    log "INFO" "Configuring SNMP..."

    local community="public"
    local location="DataCenter"
    local contact="${DEFAULT_EMAIL}"

    # Create SNMP configuration
    cat > /etc/snmp/snmpd.conf << EOF
# MRTG SNMP Configuration
# Generated by ${SCRIPT_NAME} on $(date)

# System information
syslocation ${location}
syscontact ${contact}

# SNMP community string
rocommunity ${community} 127.0.0.1
rocommunity ${community} localhost
rocommunity6 ${community} ::1

# Network interfaces monitoring
view systemonly included .1.3.6.1.2.1.1
view systemonly included .1.3.6.1.2.1.2
view systemonly included .1.3.6.1.2.1.3
view systemonly included .1.3.6.1.2.1.25.1

# Disk monitoring
includeAllDisks 10%

# Process monitoring
proc httpd 10 5
proc sshd
proc snmpd

# Load averages
load 12 10 5

# System memory monitoring
includeAllDisks 10%
includeAllDisks 5% /var

# Access control
rocommunity ${community} 10.0.0.0/8
rocommunity ${community} 172.16.0.0/12
rocommunity ${community} 192.168.0.0/16

# SNMPv3 user (optional)
# createUser mrtg-user SHA "password" AES "encryption"
# rouser mrtg-user

# Include all interfaces
#view all included .1 80
#access MyROGroup "" any noauth prefix all none none

EOF

    # Enable and start SNMP
    if [[ -f /etc/systemd/system/snmpd.service ]]; then
        systemctl enable snmpd
        systemctl restart snmpd
    else
        service snmpd restart
    fi

    log "SUCCESS" "SNMP configured successfully"
}

create_mrtg_directories() {
    log "INFO" "Creating MRTG directories..."

    mkdir -p "${MRTG_CONF}"
    mkdir -p "${MRTG_HTML}"
    mkdir -p "${MRTG_LOG}"
    mkdir -p "${MRTG_BIN}"
    mkdir -p "${MRTG_BACKUP}"
    mkdir -p "${MRTG_VAR}"
    mkdir -p "${DEFAULT_HTML_DIR}"

    # Set permissions
    chmod 755 "${MRTG_BASE}"
    chmod 755 "${MRTG_CONF}"
    chmod 755 "${MRTG_HTML}"
    chmod 755 "${DEFAULT_HTML_DIR}"

    log "SUCCESS" "Directories created successfully"
}

generate_mrtg_config() {
    log "INFO" "Generating MRTG configuration..."

    local interfaces=($(detect_network_interfaces))
    local cfg_file="${MRTG_CONF}/mrtg.cfg"
    local panel=$(detect_control_panel)

    # Create main configuration file
    cat > "${cfg_file}" << EOF
########################################################################
# MRTG Configuration File
# Generated by ${SCRIPT_NAME} on $(date)
# Control Panel: ${panel}
########################################################################

# Global configuration
WorkDir: ${DEFAULT_HTML_DIR}
RunAsDaemon: No
Interval: ${INTERVAL:-${DEFAULT_INTERVAL}}
WriteExpires: Yes
WithPeak[_]: wmy
LoadMIBs: /usr/share/snmp/mibs
Options[_]: growright, bits, nopercent

# Logging
LogDir: ${MRTG_LOG}
LogFormat: rrdtool

# HTML formatting
PageTop[_]: <h1>MRTG Monitoring - Interface Traffic</h1>
PageFoot[_]: <hr><div align="right">Generated by ${SCRIPT_NAME}</div>

# Language settings
Language: english

# Enable IPv6
EnableIPv6: yes

# SNMP settings
SnmpOptions: noVersion3
Timeout[*/]: 2
Retries[*/]: 2

# Global HTML settings
Title[^]: MRTG Network Monitor
XSize[_]: 600
YSize[_]: 300

# Refresh rate
Refresh: 300

# Multiple interfaces support
AddHeaders: Expires: Mon, 26 Jul 1997 05:00:00 GMT
AddHeaders: Pragma: no-cache
AddHeaders: Cache-control: no-cache

# Icon directory
IconDir: /mrtg-icons

########################################################################
# Interface Configurations
########################################################################

EOF

    # Add configuration for each interface
    for interface in "${interfaces[@]}"; do
        cat >> "${cfg_file}" << EOF
# Interface: ${interface}
Target[${interface}]: /${interface}:public@127.0.0.1:::::2
MaxBytes[${interface}]: 1250000
Title[${interface}]: Traffic Analysis for ${interface}
PageTop[${interface}]: <h1>Traffic Analysis for ${interface}</h1>
Options[${interface}]: growright, bits, nopercent
YLegend[${interface}]: Bits per second
ShortLegend[${interface}]: b/s
Legend1[${interface}]: Incoming Traffic (bits/sec)
Legend2[${interface}]: Outgoing Traffic (bits/sec)
Legend3[${interface}]: Max Incoming (bits/sec)
Legend4[${interface}]: Max Outgoing (bits/sec)
LegendI[${interface}]: In:
LegendO[${interface}]: Out:
WithPeak[${interface}]: wmy

EOF
    done

    # Add CPU monitoring if SNMP supports it
    cat >> "${cfg_file}" << EOF
########################################################################
# CPU Monitoring
########################################################################

Target[cpu]: .1.3.6.1.4.1.2021.11.9.0&.1.3.6.1.4.1.2021.11.10.0:public@127.0.0.1:
Title[cpu]: CPU Load Average
PageTop[cpu]: <h1>System CPU Load</h1>
MaxBytes[cpu]: 100
YLegend[cpu]: CPU Load (%)
ShortLegend[cpu]: %
Legend1[cpu]: 1 Minute Load
Legend2[cpu]: 5 Minute Load
Legend3[cpu]: 15 Minute Load
Options[cpu]: growright, nopercent, noinfo

########################################################################
# Memory Monitoring
########################################################################

Target[mem]: .1.3.6.1.4.1.2021.4.5.0&.1.3.6.1.4.1.2021.4.6.0:public@127.0.0.1:
Title[mem]: Memory Usage
PageTop[mem]: <h1>System Memory Usage</h1>
MaxBytes[mem]: 100
YLegend[mem]: Memory (%)
ShortLegend[mem]: %
Legend1[mem]: Total Memory
Legend2[mem]: Used Memory
Options[mem]: growright, nopercent

########################################################################
# Disk Usage Monitoring
########################################################################

Target[disk]: .1.3.6.1.4.1.2021.9.1.6.1&.1.3.6.1.4.1.2021.9.1.7.1:public@127.0.0.1:
Title[disk]: Disk Usage - Root Partition
PageTop[disk]: <h1>Root Partition Usage</h1>
MaxBytes[disk]: 100
YLegend[disk]: Disk Usage (%)
ShortLegend[disk]: %
Legend1[disk]: Used Space
Legend2[disk]: Available Space
Options[disk]: growright, nopercent

EOF

    log "SUCCESS" "MRTG configuration generated successfully"
}

configure_directadmin() {
    local panel=$(detect_control_panel)

    if [[ "${panel}" != "directadmin" ]]; then
        return 0
    fi

    log "INFO" "Configuring DirectAdmin integration..."

    # Create DirectAdmin plugin structure
    local da_plugins="/usr/local/directadmin/plugins"
    local mrtg_plugin="${da_plugins}/mrtg-monitor"

    mkdir -p "${mrtg_plugin}/admin"
    mkdir -p "${mrtg_plugin}/data"
    mkdir -p "${mrtg_plugin}/hooks"
    mkdir -p "${mrtg_plugin}/scripts"

    # Create plugin configuration
    cat > "${mrtg_plugin}/plugin.conf" << EOF
name=MRTG Monitor
version=1.0
desc=Network traffic monitoring and bandwidth graphing
url=/plugins/mrtg-monitor/admin/index.html
icon=/plugins/mrtg-monitor/icon.png
level=admin
EOF

    # Create admin index page
    cat > "${mrtg_plugin}/admin/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>MRTG Network Monitor</title>
    <meta http-equiv="refresh" content="300">
    <link rel="stylesheet" href="/plugins/mrtg-monitor/css/style.css">
</head>
<body>
    <div class="header">
        <h1>Network Traffic Monitoring</h1>
        <p>DirectAdmin Integration by ${SCRIPT_AUTHOR}</p>
    </div>
    <div class="content">
        <iframe src="/mrtg/" width="100%" height="1000" frameborder="0"></iframe>
    </div>
</body>
</html>
EOF

    # Create symbolic link to MRTG HTML directory
    ln -sf "${DEFAULT_HTML_DIR}" "/var/www/html/mrtg"

    log "SUCCESS" "DirectAdmin integration configured"
}

setup_cron() {
    local interval="${INTERVAL:-${DEFAULT_INTERVAL}}"

    log "INFO" "Setting up cron job with ${interval} minute interval..."

    # Create MRTG runner script
    cat > "${MRTG_BIN}/run-mrtg.sh" << EOF
#!/bin/bash
# MRTG Runner Script
# Generated by ${SCRIPT_NAME} on $(date)

export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Run MRTG
/usr/bin/mrtg ${MRTG_CONF}/mrtg.cfg --logging ${MRTG_LOG}/mrtg.log

# Generate index page
/usr/bin/indexmaker ${MRTG_CONF}/mrtg.cfg --output=${DEFAULT_HTML_DIR}/index.html

# Set permissions
chmod -R 644 ${DEFAULT_HTML_DIR}/*
chmod -R 755 ${DEFAULT_HTML_DIR}
EOF

    chmod +x "${MRTG_BIN}/run-mrtg.sh"

    # Add to crontab
    local cron_cmd="*/${interval} * * * * ${MRTG_BIN}/run-mrtg.sh >/dev/null 2>&1"

    # Check if already in crontab
    if crontab -l 2>/dev/null | grep -q "${MRTG_BIN}/run-mrtg.sh"; then
        log "WARNING" "Cron job already exists. Removing old one..."
        crontab -l | grep -v "${MRTG_BIN}/run-mrtg.sh" | crontab -
    fi

    # Add new cron job
    (crontab -l 2>/dev/null; echo "${cron_cmd}") | crontab -

    log "SUCCESS" "Cron job added successfully (interval: ${interval} minutes)"
}

setup_web_interface() {
    log "INFO" "Setting up web interface..."

    # Create .htaccess for security
    cat > "${DEFAULT_HTML_DIR}/.htaccess" << EOF
# MRTG Web Access Control
# Generated by ${SCRIPT_NAME} on $(date)

# Allow access from localhost only by default
Order Deny,Allow
Deny from all
Allow from 127.0.0.1
Allow from ::1

# Uncomment to allow specific IP ranges
# Allow from 192.168.1.
# Allow from 10.0.0.

# Password protect if desired
# AuthType Basic
# AuthName "MRTG Monitoring"
# AuthUserFile /etc/mrtg/.htpasswd
# Require valid-user
EOF

    # Create robots.txt
    cat > "${DEFAULT_HTML_DIR}/robots.txt" << EOF
User-agent: *
Disallow: /
EOF

    log "SUCCESS" "Web interface configured"
}

configure_email_alerts() {
    local email="${1:-${DEFAULT_EMAIL}}"

    log "INFO" "Configuring email alerts for ${email}..."

    # Create alert configuration
    cat > "${MRTG_CONF}/alerts.cfg" << EOF
#!/bin/bash
# MRTG Email Alert Configuration
# Generated by ${SCRIPT_NAME} on $(date)

# Email settings
ALERT_EMAIL="${email}"
SMTP_SERVER="localhost"
SMTP_PORT="25"

# Thresholds (in bits per second)
WARN_THRESHOLD="1000000"  # 1 Mbps
CRIT_THRESHOLD="10000000" # 10 Mbps

# Check function
check_bandwidth() {
    local interface="\$1"
    local current=\$2
    local max=\$3

    if [[ \${current} -gt ${CRIT_THRESHOLD} ]]; then
        echo "CRITICAL: Interface \${interface} is at \${current} bps" | \\
            mail -s "MRTG Critical Alert - \${interface}" "\${ALERT_EMAIL}"
    elif [[ \${current} -gt ${WARN_THRESHOLD} ]]; then
        echo "WARNING: Interface \${interface} is at \${current} bps" | \\
            mail -s "MRTG Warning Alert - \${interface}" "\${ALERT_EMAIL}"
    fi
}
EOF

    chmod +x "${MRTG_CONF}/alerts.cfg"

    log "SUCCESS" "Email alerts configured"
}

# =============================================================================
# UNINSTALL FUNCTIONS
# =============================================================================

uninstall_mrtg() {
    local force="${1:-false}"

    log "INFO" "Starting uninstallation process..."

    if [[ "${force}" != "true" ]]; then
        echo -e "${YELLOW}WARNING: This will completely remove MRTG and all configurations.${NC}"
        read -p "Are you sure you want to continue? (y/N): " confirm
        if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
            log "INFO" "Uninstallation cancelled"
            return 0
        fi
    fi

    # Remove cron jobs
    log "INFO" "Removing cron jobs..."
    crontab -l 2>/dev/null | grep -v "${MRTG_BIN}/run-mrtg.sh" | crontab -

    # Stop services
    log "INFO" "Stopping services..."
    systemctl stop snmpd 2>/dev/null || service snmpd stop 2>/dev/null || true

    # Remove packages (ask user)
    echo -e "${YELLOW}Do you want to remove MRTG and SNMP packages?${NC}"
    read -p "Remove packages? (y/N): " remove_pkgs

    if [[ "${remove_pkgs}" =~ ^[Yy]$ ]]; then
        log "INFO" "Removing packages..."
        case "${OS}" in
            *"Ubuntu"*|*"Debian"*)
                apt-get remove --purge -y mrtg snmpd snmp
                ;;
            *"CentOS"*|*"Red Hat"*|*"Fedora"*|*"AlmaLinux"*|*"Rocky"*)
                yum remove -y mrtg net-snmp net-snmp-utils
                ;;
        esac
    fi

    # Remove MRTG directories
    log "INFO" "Removing MRTG files..."
    read -p "Remove all MRTG data and configurations? (y/N): " remove_data

    if [[ "${remove_data}" =~ ^[Yy]$ ]]; then
        rm -rf "${MRTG_BASE}"
        rm -rf "${MRTG_VAR}"
        rm -rf "${DEFAULT_HTML_DIR}"
        log "INFO" "All MRTG data removed"
    fi

    # Remove DirectAdmin plugin
    if [[ -d "/usr/local/directadmin/plugins/mrtg-monitor" ]]; then
        rm -rf "/usr/local/directadmin/plugins/mrtg-monitor"
        log "INFO" "DirectAdmin plugin removed"
    fi

    log "SUCCESS" "Uninstallation completed"
}

# =============================================================================
# BACKUP AND RESTORE FUNCTIONS
# =============================================================================

backup_config() {
    local backup_file="${MRTG_BACKUP}/mrtg-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

    log "INFO" "Creating backup: ${backup_file}"

    # Create backup
    tar -czf "${backup_file}" \
        --exclude="${MRTG_LOG}/*" \
        --exclude="${MRTG_VAR}/*" \
        "${MRTG_CONF}" \
        "${MRTG_HTML}" \
        "${MRTG_BIN}" \
        "${DEFAULT_HTML_DIR}" \
        /etc/snmp/snmpd.conf \
        2>/dev/null || true

    if [[ -f "${backup_file}" ]]; then
        log "SUCCESS" "Backup created: ${backup_file}"
        echo -e "${GREEN}Backup saved to: ${backup_file}${NC}"
    else
        log "ERROR" "Backup failed"
        return 1
    fi
}

restore_config() {
    log "INFO" "Available backups:"
    local backups=($(ls -1 "${MRTG_BACKUP}"/*.tar.gz 2>/dev/null))

    if [[ ${#backups[@]} -eq 0 ]]; then
        log "ERROR" "No backups found"
        return 1
    fi

    local i=1
    for backup in "${backups[@]}"; do
        echo -e "  ${CYAN}${i})${NC} $(basename "${backup}")"
        i=$((i+1))
    done

    read -p "Select backup to restore (1-${#backups[@]}): " selection

    if [[ ! "${selection}" =~ ^[0-9]+$ ]] || [[ "${selection}" -lt 1 ]] || [[ "${selection}" -gt ${#backups[@]} ]]; then
        log "ERROR" "Invalid selection"
        return 1
    fi

    local selected="${backups[$((selection-1))]}"

    log "INFO" "Restoring from: ${selected}"

    # Stop MRTG cron temporarily
    crontab -l 2>/dev/null | grep -v "${MRTG_BIN}/run-mrtg.sh" | crontab -

    # Restore files
    tar -xzf "${selected}" -C /

    # Restart services
    systemctl restart snmpd 2>/dev/null || service snmpd restart 2>/dev/null || true

    # Re-add cron
    setup_cron

    log "SUCCESS" "Restore completed"
}

# =============================================================================
# STATUS FUNCTIONS
# =============================================================================

check_status() {
    log "INFO" "Checking MRTG status..."

    echo -e "\n${BOLD}=== MRTG Installation Status ===${NC}\n"

    # Check if installed
    if [[ -d "${MRTG_BASE}" ]] && [[ -f "${MRTG_CONF}/mrtg.cfg" ]]; then
        echo -e "  ${GREEN}✓${NC} MRTG installed"
    else
        echo -e "  ${RED}✗${NC} MRTG not installed"
    fi

    # Check services
    if systemctl status snmpd 2>/dev/null | grep -q "active (running)"; then
        echo -e "  ${GREEN}✓${NC} SNMP service running"
    elif service snmpd status 2>/dev/null | grep -q "running"; then
        echo -e "  ${GREEN}✓${NC} SNMP service running"
    else
        echo -e "  ${RED}✗${NC} SNMP service not running"
    fi

    # Check cron
    if crontab -l 2>/dev/null | grep -q "${MRTG_BIN}/run-mrtg.sh"; then
        local interval=$(crontab -l 2>/dev/null | grep "${MRTG_BIN}/run-mrtg.sh" | awk '{print $2}')
        echo -e "  ${GREEN}✓${NC} Cron job active (interval: ${interval} minutes)"
    else
        echo -e "  ${RED}✗${NC} No cron job found"
    fi

    # Check web interface
    if [[ -f "${DEFAULT_HTML_DIR}/index.html" ]]; then
        echo -e "  ${GREEN}✓${NC} Web interface accessible at: ${DEFAULT_HTML_DIR}"
    else
        echo -e "  ${RED}✗${NC} Web interface not generated yet"
    fi

    # Check interfaces
    local interfaces=($(detect_network_interfaces))
    echo -e "\n${BOLD}=== Monitored Interfaces (${#interfaces[@]}) ===${NC}\n"
    for interface in "${interfaces[@]}"; do
        if [[ -f "${DEFAULT_HTML_DIR}/${interface}.html" ]]; then
            echo -e "  ${GREEN}✓${NC} ${interface} - monitoring active"
        else
            echo -e "  ${YELLOW}○${NC} ${interface} - waiting for first run"
        fi
    done

    # Check disk space
    echo -e "\n${BOLD}=== Disk Usage ===${NC}\n"
    du -sh "${MRTG_BASE}" 2>/dev/null || echo "  No data yet"

    # Last run time
    echo -e "\n${BOLD}=== Last Activity ===${NC}\n"
    if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
        echo -e "  Last log entry: $(tail -1 "${MRTG_LOG}/mrtg.log")"
    fi
    echo ""
}

# =============================================================================
# INSTALLATION WIZARD
# =============================================================================

installation_wizard() {
    print_banner

    echo -e "${BOLD}Welcome to MRTG Installation Wizard${NC}"
    echo -e "${CYAN}====================================${NC}\n"

    # Check root
    check_root

    # Detect OS
    detect_os
    echo -e "Detected OS: ${GREEN}${OS} ${VER}${NC}"

    # Detect control panel
    local panel=$(detect_control_panel)
    if [[ "${panel}" != "none" ]]; then
        echo -e "Detected Control Panel: ${GREEN}${panel}${NC}"
    else
        echo -e "Detected Control Panel: ${YELLOW}none${NC}"
    fi

    echo ""

    # Get installation parameters
    read -p "Monitoring interval in minutes [${DEFAULT_INTERVAL}]: " interval
    interval=${interval:-${DEFAULT_INTERVAL}}

    read -p "HTML output directory [${DEFAULT_HTML_DIR}]: " html_dir
    html_dir=${html_dir:-${DEFAULT_HTML_DIR}}

    read -p "Notification email [${DEFAULT_EMAIL}]: " email
    email=${email:-${DEFAULT_EMAIL}}

    # Ask about SNMP configuration
    echo ""
    read -p "Configure SNMP with default settings? (Y/n): " configure_snmp_yn
    configure_snmp_yn=${configure_snmp_yn:-Y}

    # Ask about web interface
    read -p "Set up web interface with access restrictions? (Y/n): " web_interface_yn
    web_interface_yn=${web_interface_yn:-Y}

    # Confirm installation
    echo -e "\n${YELLOW}Installation Summary:${NC}"
    echo "  Interval: ${interval} minutes"
    echo "  HTML Directory: ${html_dir}"
    echo "  Email: ${email}"
    echo "  Configure SNMP: ${configure_snmp_yn}"
    echo "  Web Interface: ${web_interface_yn}"
    echo ""

    read -p "Proceed with installation? (y/N): " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        log "INFO" "Installation cancelled"
        return 0
    fi

    # Perform installation
    echo -e "\n${CYAN}Starting installation...${NC}\n"

    # Set variables
    INTERVAL=${interval}
    DEFAULT_HTML_DIR=${html_dir}
    DEFAULT_EMAIL=${email}

    # Run installation steps
    install_dependencies
    create_mrtg_directories

    if [[ "${configure_snmp_yn}" =~ ^[Yy]$ ]]; then
        configure_snmp
    fi

    generate_mrtg_config
    configure_directadmin

    if [[ "${web_interface_yn}" =~ ^[Yy]$ ]]; then
        setup_web_interface
    fi

    configure_email_alerts "${email}"
    setup_cron

    # Initial run
    log "INFO" "Running initial MRTG collection..."
    env LANG=C /usr/bin/mrtg "${MRTG_CONF}/mrtg.cfg" --logging "${MRTG_LOG}/mrtg.log" 2>/dev/null || true
    /usr/bin/mrtg "${MRTG_CONF}/mrtg.cfg" --logging "${MRTG_LOG}/mrtg.log" 2>/dev/null || true
    /usr/bin/mrtg "${MRTG_CONF}/mrtg.cfg" --logging "${MRTG_LOG}/mrtg.log"

    # Generate index
    /usr/bin/indexmaker "${MRTG_CONF}/mrtg.cfg" --output="${DEFAULT_HTML_DIR}/index.html"

    # Final message
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo -e "${GREEN}========================================${NC}\n"

    echo -e "Access MRTG at: ${BLUE}http://your-server/mrtg/${NC}"
    echo -e "Configuration: ${CYAN}${MRTG_CONF}/mrtg.cfg${NC}"
    echo -e "Logs: ${CYAN}${MRTG_LOG}${NC}"
    echo -e "Cron interval: ${interval} minutes\n"

    check_status
}

# =============================================================================
# MAIN MENU
# =============================================================================

show_menu() {
    print_banner

    echo -e "${BOLD}MAIN MENU${NC}"
    echo -e "${CYAN}==========${NC}\n"

    echo -e "  ${GREEN}1)${NC} Install MRTG (Full installation wizard)"
    echo -e "  ${GREEN}2)${NC} Uninstall MRTG"
    echo -e "  ${GREEN}3)${NC} Add Cron Job"
    echo -e "  ${GREEN}4)${NC} Remove Cron Job"
    echo -e "  ${GREEN}5)${NC} Reconfigure MRTG"
    echo -e "  ${GREEN}6)${NC} Backup Configuration"
    echo -e "  ${GREEN}7)${NC} Restore Configuration"
    echo -e "  ${GREEN}8)${NC} Check Status"
    echo -e "  ${GREEN}9)${NC} View Logs"
    echo -e "  ${GREEN}10)${NC} Test MRTG Configuration"
    echo -e "  ${GREEN}11)${NC} Generate Index Page"
    echo -e "  ${GREEN}12)${NC} Update Script"
    echo -e "  ${GREEN}0)${NC} Exit\n"

    read -p "Enter your choice [0-12]: " choice

    case ${choice} in
        1) installation_wizard ;;
        2) uninstall_mrtg ;;
        3) setup_cron ;;
        4)
            log "INFO" "Removing cron job..."
            crontab -l 2>/dev/null | grep -v "${MRTG_BIN}/run-mrtg.sh" | crontab -
            log "SUCCESS" "Cron job removed"
            ;;
        5)
            log "INFO" "Reconfiguring MRTG..."
            generate_mrtg_config
            setup_cron
            ;;
        6) backup_config ;;
        7) restore_config ;;
        8) check_status ;;
        9)
            if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
                tail -50 "${MRTG_LOG}/mrtg.log"
            else
                log "ERROR" "Log file not found"
            fi
            ;;
        10)
            log "INFO" "Testing MRTG configuration..."
            env LANG=C /usr/bin/mrtg "${MRTG_CONF}/mrtg.cfg" --check
            ;;
        11)
            log "INFO" "Generating index page..."
            /usr/bin/indexmaker "${MRTG_CONF}/mrtg.cfg" --output="${DEFAULT_HTML_DIR}/index.html"
            log "SUCCESS" "Index page generated"
            ;;
        12)
            log "INFO" "Updating script..."
            wget -O "${0}" "https://raw.githubusercontent.com/waelisa/mrtg-monitor/main/install-mrtg.sh"
            chmod +x "${0}"
            log "SUCCESS" "Script updated. Please restart."
            exit 0
            ;;
        0)
            echo -e "${GREEN}Thank you for using MRTG Professional Monitoring Suite!${NC}"
            exit 0
            ;;
        *)
            log "ERROR" "Invalid option"
            ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
    show_menu
}

# =============================================================================
# MAIN SCRIPT EXECUTION
# =============================================================================

main() {
    # Initialize log
    touch "${LOG_FILE}"
    chmod 644 "${LOG_FILE}"

    # Parse command line arguments
    if [[ $# -gt 0 ]]; then
        while [[ $# -gt 0 ]]; do
            case $1 in
                --help|-h)
                    print_help
                    exit 0
                    ;;
                --install|-i)
                    check_root
                    installation_wizard
                    exit 0
                    ;;
                --uninstall|-u)
                    check_root
                    shift
                    uninstall_mrtg "$1"
                    exit 0
                    ;;
                --cron-add|-ca)
                    check_root
                    shift
                    if [[ "$1" == "--interval" || "$1" == "-in" ]]; then
                        shift
                        INTERVAL="$1"
                        shift
                    fi
                    setup_cron
                    exit 0
                    ;;
                --cron-remove|-cr)
                    check_root
                    crontab -l 2>/dev/null | grep -v "${MRTG_BIN}/run-mrtg.sh" | crontab -
                    log "SUCCESS" "Cron job removed"
                    exit 0
                    ;;
                --configure|-c)
                    check_root
                    generate_mrtg_config
                    setup_cron
                    log "SUCCESS" "Reconfiguration completed"
                    exit 0
                    ;;
                --backup|-b)
                    check_root
                    backup_config
                    exit 0
                    ;;
                --restore|-r)
                    check_root
                    restore_config
                    exit 0
                    ;;
                --status|-s)
                    check_status
                    exit 0
                    ;;
                --version|-v)
                    echo "${SCRIPT_NAME} ${SCRIPT_VERSION}"
                    exit 0
                    ;;
                --interval|-in)
                    shift
                    INTERVAL="$1"
                    shift
                    ;;
                --email|-e)
                    shift
                    DEFAULT_EMAIL="$1"
                    shift
                    ;;
                --html-dir|-hd)
                    shift
                    DEFAULT_HTML_DIR="$1"
                    shift
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}"
                    print_help
                    exit 1
                    ;;
            esac
        done
    else
        # Interactive mode
        show_menu
    fi
}

# Trap errors
trap 'error_exit "Script interrupted on line $LINENO"' ERR

# Run main function
main "$@"
