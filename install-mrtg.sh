#!/bin/bash
#
# MRTG Professional Monitoring Suite - Enterprise Ready
# Intelligent detection - Works with existing server configurations
# Version: v1.2.0 | Build Date: 02/27/2026
# Author: Wael Isa | GitHub: https://github.com/waelisa/mrtg
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
# ⚠️  SAFETY FIRST: This script NEVER installs/overwrites web servers
# ⚠️  It detects and uses existing web server configurations
# ⚠️  Works with: Apache, Nginx, LiteSpeed, OpenLiteSpeed, Caddy
#
# Features:
#   • Intelligent web server detection (Apache/Nginx/LiteSpeed/Caddy)
#   • No web server installation - uses existing setup
#   • CSF firewall integration with safety checks
#   • Custom SNMP community strings (no more 'public')
#   • Full uninstall with configuration backup
#   • DirectAdmin/cPanel/Plesk detection
#   • Multi-distro support (Debian, Ubuntu, CentOS, Alma, Rocky)
#   • Dry-run mode for testing
#   • Configuration validation before applying
#
# Usage:
#   ./install-mrtg.sh --install           # Interactive installation
#   ./install-mrtg.sh --uninstall          # Complete removal
#   ./install-mrtg.sh --dry-run            # Test without changes
#   ./install-mrtg.sh --help               # Show help
#
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# COLOR CODES
# =============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================
readonly SCRIPT_VERSION="v1.2.0"
readonly SCRIPT_AUTHOR="Wael Isa"
readonly SCRIPT_URL="https://github.com/waelisa/mrtg"
readonly LOG_FILE="/var/log/mrtg-installer.log"
readonly CONFIG_BACKUP_DIR="/root/mrtg-backups"

# Installation paths (configurable)
MRTG_BASE="/usr/local/mrtg"
MRTG_CONF="${MRTG_BASE}/conf"
MRTG_LOG="${MRTG_BASE}/logs"
MRTG_HTML="${MRTG_BASE}/html"
MRTG_BIN="${MRTG_BASE}/bin"
MRTG_VAR="/var/lib/mrtg"

# Default values (will be detected/overridden)
DEFAULT_INTERVAL=5
DEFAULT_EMAIL="root@localhost"
SNMP_COMMUNITY=""
WEB_ROOT=""
WEB_USER=""
WEB_GROUP=""
WEB_SERVER="unknown"

# Dry run mode
DRY_RUN=false

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"

    if [[ "${DRY_RUN}" == true && "${level}" != "ERROR" ]]; then
        echo -e "${YELLOW}[DRY RUN]${NC} ${message}"
    else
        case "${level}" in
            "ERROR")   echo -e "${RED}[ERROR]${NC} ${message}" ;;
            "WARNING") echo -e "${YELLOW}[WARNING]${NC} ${message}" ;;
            "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} ${message}" ;;
            "INFO")    echo -e "${CYAN}[INFO]${NC} ${message}" ;;
            *)         echo -e "${message}" ;;
        esac
    fi
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

confirm_action() {
    local prompt="$1"
    local default="${2:-N}"

    if [[ "${DRY_RUN}" == true ]]; then
        return 0
    fi

    read -p "${prompt} (y/N): " response
    if [[ "${response}" =~ ^[Yy]$ ]]; then
        return 0
    fi
    return 1
}

# =============================================================================
# DETECTION FUNCTIONS (NO ASSUMPTIONS)
# =============================================================================

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        OS_ID=$ID
    else
        OS="Unknown"
        VER="Unknown"
        OS_ID="unknown"
    fi
    log "INFO" "Detected OS: ${OS} ${VER}"
}

detect_control_panel() {
    local panel="none"

    if [[ -d /usr/local/directadmin ]]; then
        panel="directadmin"
        log "INFO" "DirectAdmin control panel detected"
    elif [[ -d /usr/local/cpanel ]]; then
        panel="cpanel"
        log "INFO" "cPanel control panel detected"
    elif [[ -d /usr/local/psa ]]; then
        panel="plesk"
        log "INFO" "Plesk control panel detected"
    elif [[ -d /usr/local/ispconfig ]]; then
        panel="ispconfig"
        log "INFO" "ISPConfig detected"
    elif [[ -d /usr/local/virtualmin ]]; then
        panel="virtualmin"
        log "INFO" "Virtualmin detected"
    fi

    echo "${panel}"
}

detect_web_server() {
    log "INFO" "Detecting web server (without installing anything)..."

    # Check for running web servers (most reliable)
    if pgrep -x "nginx" >/dev/null 2>&1; then
        WEB_SERVER="nginx"
        WEB_USER=$(ps aux | grep nginx | grep -v grep | head -1 | awk '{print $1}' || echo "www-data")
        WEB_GROUP=$(id -gn ${WEB_USER} 2>/dev/null || echo "www-data")
        log "SUCCESS" "Detected running Nginx server"

    elif pgrep -x "httpd" >/dev/null 2>&1 || pgrep -x "apache2" >/dev/null 2>&1; then
        WEB_SERVER="apache"
        if [[ -f /etc/redhat-release ]]; then
            WEB_USER="apache"
            WEB_GROUP="apache"
        else
            WEB_USER="www-data"
            WEB_GROUP="www-data"
        fi
        log "SUCCESS" "Detected running Apache server"

    elif pgrep -x "litespeed" >/dev/null 2>&1 || pgrep -x "lshttpd" >/dev/null 2>&1; then
        WEB_SERVER="litespeed"
        WEB_USER="nobody"
        WEB_GROUP="nobody"
        log "SUCCESS" "Detected running LiteSpeed server"

    elif pgrep -x "caddy" >/dev/null 2>&1; then
        WEB_SERVER="caddy"
        WEB_USER=$(ps aux | grep caddy | grep -v grep | head -1 | awk '{print $1}' || echo "caddy")
        WEB_GROUP=$(id -gn ${WEB_USER} 2>/dev/null || echo "caddy")
        log "SUCCESS" "Detected running Caddy server"

    else
        # Fallback: Check for installed but not running
        if command -v nginx >/dev/null 2>&1; then
            WEB_SERVER="nginx"
            WEB_USER="www-data"
            WEB_GROUP="www-data"
            log "WARNING" "Nginx installed but not running"
        elif command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
            WEB_SERVER="apache"
            if [[ -f /etc/redhat-release ]]; then
                WEB_USER="apache"
                WEB_GROUP="apache"
            else
                WEB_USER="www-data"
                WEB_GROUP="www-data"
            fi
            log "WARNING" "Apache installed but not running"
        else
            log "ERROR" "No supported web server detected!"
            log "INFO" "Please install Nginx, Apache, or LiteSpeed first"
            return 1
        fi
    fi

    # Detect web root based on server type and OS
    detect_web_root
}

detect_web_root() {
    # Common web roots based on server type and OS
    local panel=$(detect_control_panel)

    # Panel-specific paths first
    case "${panel}" in
        "directadmin")
            WEB_ROOT="/var/www/html"
            ;;
        "cpanel")
            if [[ -d "/usr/local/apache/htdocs" ]]; then
                WEB_ROOT="/usr/local/apache/htdocs"
            else
                WEB_ROOT="/home/*/public_html"  # Multiple user dirs
            fi
            ;;
        "plesk")
            WEB_ROOT="/var/www/vhosts"
            ;;
        *)
            # Generic paths based on web server
            case "${WEB_SERVER}" in
                "nginx")
                    if [[ -d "/usr/share/nginx/html" ]]; then
                        WEB_ROOT="/usr/share/nginx/html"
                    elif [[ -d "/var/www/html" ]]; then
                        WEB_ROOT="/var/www/html"
                    elif [[ -d "/srv/www/htdocs" ]]; then
                        WEB_ROOT="/srv/www/htdocs"
                    fi
                    ;;
                "apache")
                    if [[ -d "/var/www/html" ]]; then
                        WEB_ROOT="/var/www/html"
                    elif [[ -d "/var/www" ]]; then
                        WEB_ROOT="/var/www"
                    elif [[ -d "/srv/www/htdocs" ]]; then
                        WEB_ROOT="/srv/www/htdocs"
                    fi
                    ;;
                "litespeed")
                    if [[ -d "/usr/local/lsws/htdocs" ]]; then
                        WEB_ROOT="/usr/local/lsws/htdocs"
                    fi
                    ;;
                "caddy")
                    if [[ -d "/var/www/html" ]]; then
                        WEB_ROOT="/var/www/html"
                    fi
                    ;;
            esac
            ;;
    esac

    # Verify web root exists
    if [[ ! -d "${WEB_ROOT}" ]]; then
        log "WARNING" "Default web root ${WEB_ROOT} not found"
        # Try to find any writable web directory
        WEB_ROOT=$(find /var/www -type d -name "html" -o -name "htdocs" 2>/dev/null | head -1)
        if [[ -z "${WEB_ROOT}" ]]; then
            WEB_ROOT="/var/www/html"  # Fallback, will create if needed
        fi
    fi

    log "INFO" "Web root set to: ${WEB_ROOT}"
}

detect_network_interfaces() {
    local interfaces=()

    # Get all network interfaces except loopback and virtual
    for interface in $(ls /sys/class/net/ | grep -vE 'lo|virbr|docker|veth'); do
        # Check if interface has an IP address
        if ip addr show "${interface}" 2>/dev/null | grep -q "inet "; then
            interfaces+=("${interface}")
        fi
    done

    # If no interfaces found, fallback to all except loopback
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        for interface in $(ls /sys/class/net/ | grep -v lo); do
            interfaces+=("${interface}")
        done
    fi

    echo "${interfaces[@]}"
}

# =============================================================================
# SAFE INSTALLATION FUNCTIONS (NO WEB SERVER INSTALLATION)
# =============================================================================

install_dependencies() {
    log "INFO" "Installing only MRTG and SNMP packages (no web server)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would install: mrtg, snmpd, snmp, perl modules"
        return 0
    fi

    case "${OS_ID}" in
        ubuntu|debian)
            apt-get update -y
            apt-get install -y mrtg snmpd snmp libsnmp-dev \
                               perl libwww-perl libcrypt-ssleay-perl \
                               libdigest-hmac-perl libio-socket-ssl-perl \
                               libnet-snmp-perl --no-install-recommends
            ;;
        centos|rhel|almalinux|rocky|fedora)
            # Check if epel is needed
            if ! rpm -q epel-release >/dev/null 2>&1; then
                if [[ "${OS_ID}" == "centos" ]] || [[ "${OS_ID}" == "rhel" ]]; then
                    yum install -y epel-release
                fi
            fi
            yum install -y mrtg net-snmp net-snmp-utils \
                           perl-libwww-perl perl-Crypt-SSLeay \
                           perl-Digest-HMAC perl-IO-Socket-SSL \
                           perl-Net-SNMP
            ;;
        *)
            error_exit "Unsupported OS: ${OS}"
            ;;
    esac

    log "SUCCESS" "Dependencies installed successfully"
}

configure_snmp() {
    log "INFO" "Configuring SNMP with custom community string..."

    # Generate random community if not set
    if [[ -z "${SNMP_COMMUNITY}" ]]; then
        SNMP_COMMUNITY="mrtg_$(openssl rand -hex 8)"
        log "INFO" "Generated secure community string: ${SNMP_COMMUNITY}"
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure SNMP with community: ${SNMP_COMMUNITY}"
        return 0
    fi

    # Backup existing config
    if [[ -f /etc/snmp/snmpd.conf ]]; then
        cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.backup.$(date +%Y%m%d)
    fi

    # Create secure SNMP configuration
    cat > /etc/snmp/snmpd.conf << EOF
########################################################################
# SNMPd Configuration for MRTG
# Generated by MRTG Professional Suite on $(date)
# Community: ${SNMP_COMMUNITY}
########################################################################

# Only allow read-only access from localhost with custom community
rocommunity ${SNMP_COMMUNITY} 127.0.0.1
rocommunity6 ${SNMP_COMMUNITY} ::1

# System information
syslocation "Production Server"
syscontact ${DEFAULT_EMAIL}

# Network interfaces monitoring
view systemonly included .1.3.6.1.2.1.1
view systemonly included .1.3.6.1.2.1.2
view systemonly included .1.3.6.1.2.1.3

# Disk monitoring
includeAllDisks 10%

# Process monitoring (common services)
proc httpd 10 5
proc nginx 10 5
proc sshd
proc snmpd

# Load averages
load 12 10 5

# Memory monitoring
view systemonly included .1.3.6.1.4.1.2021.4

# Disable default community
com2sec paranoid default public
group paranoid v1 paranoid
group paranoid v2c paranoid
access paranoid "" any noauth exact system none none

EOF

    # Restart SNMP
    if systemctl list-units --full -all | grep -Fq 'snmpd.service'; then
        systemctl enable snmpd
        systemctl restart snmpd
    else
        service snmpd restart
    fi

    log "SUCCESS" "SNMP configured with secure community string"
}

configure_firewall() {
    log "INFO" "Checking firewall configuration..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure firewall to allow SNMP (UDP 161)"
        return 0
    fi

    # CSF (Common on DirectAdmin/cPanel)
    if [[ -f /etc/csf/csf.conf ]]; then
        log "INFO" "CSF Firewall detected"

        # Backup CSF config
        cp /etc/csf/csf.conf /etc/csf/csf.conf.backup.$(date +%Y%m%d)

        # Add SNMP port if not exists
        if ! grep -q "161" /etc/csf/csf.conf; then
            sed -i 's/^UDP_IN = "\(.*\)"/UDP_IN = "\1,161"/' /etc/csf/csf.conf
            sed -i 's/^UDP_OUT = "\(.*\)"/UDP_OUT = "\1,161"/' /etc/csf/csf.conf
            csf -r >/dev/null 2>&1
            log "SUCCESS" "CSF updated to allow SNMP"
        else
            log "INFO" "SNMP port already allowed in CSF"
        fi

    # Firewalld
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log "INFO" "Firewalld detected"
        firewall-cmd --permanent --add-service=snmp
        firewall-cmd --reload >/dev/null
        log "SUCCESS" "Firewalld updated"

    # UFW
    elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
        log "INFO" "UFW detected"
        ufw allow snmp
        log "SUCCESS" "UFW updated"

    # iptables (basic check)
    elif command -v iptables >/dev/null 2>&1; then
        log "WARNING" "Manual iptables detected - please ensure UDP port 161 is open"
    else
        log "INFO" "No active firewall detected"
    fi
}

create_directories() {
    log "INFO" "Creating MRTG directories..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would create directories: ${MRTG_BASE}, ${MRTG_CONF}, etc"
        return 0
    fi

    mkdir -p "${MRTG_CONF}"
    mkdir -p "${MRTG_LOG}"
    mkdir -p "${MRTG_HTML}"
    mkdir -p "${MRTG_BIN}"
    mkdir -p "${MRTG_VAR}"
    mkdir -p "${CONFIG_BACKUP_DIR}"

    # Create web directory if it doesn't exist
    if [[ ! -d "${WEB_ROOT}/mrtg" ]]; then
        mkdir -p "${WEB_ROOT}/mrtg"
    fi

    # Set proper permissions
    chmod 755 "${MRTG_BASE}"
    chmod 750 "${MRTG_CONF}"
    chmod 755 "${MRTG_LOG}"
    chmod 755 "${WEB_ROOT}/mrtg"

    log "SUCCESS" "Directories created"
}

generate_mrtg_config() {
    log "INFO" "Generating MRTG configuration with hardware detection..."

    local cfg_file="${MRTG_CONF}/mrtg.cfg"
    local mrtg_path=$(command -v mrtg || echo "/usr/bin/mrtg")
    local cfgmaker_path=$(command -v cfgmaker || echo "/usr/bin/cfgmaker")
    local indexmaker_path=$(command -v indexmaker || echo "/usr/bin/indexmaker")

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would generate MRTG config using: ${cfgmaker_path}"
        return 0
    fi

    # Use cfgmaker to detect hardware automatically
    ${cfgmaker_path} \
        --global "WorkDir: ${WEB_ROOT}/mrtg" \
        --global "Options[_]: growright, bits, nopercent" \
        --global "LogDir: ${MRTG_LOG}" \
        --global "RunAsDaemon: No" \
        --global "Interval: ${INTERVAL:-${DEFAULT_INTERVAL}}" \
        --global "EnableIPv6: yes" \
        --global "Language: english" \
        --snmp-options=:::::2 \
        "${SNMP_COMMUNITY}@127.0.0.1" > "${cfg_file}" 2>/dev/null || true

    # Check if cfgmaker succeeded
    if [[ ! -s "${cfg_file}" ]]; then
        log "WARNING" "cfgmaker failed, using template configuration"
        generate_template_config "${cfg_file}"
    fi

    # Append system monitoring
    cat >> "${cfg_file}" << EOF

########################################################################
# System Health Monitoring
########################################################################

# CPU Load
Target[cpu]: .1.3.6.1.4.1.2021.11.9.0&.1.3.6.1.4.1.2021.11.10.0:${SNMP_COMMUNITY}@127.0.0.1:
Title[cpu]: CPU Load Average
PageTop[cpu]: <h1>System CPU Load</h1>
MaxBytes[cpu]: 100
ShortLegend[cpu]: %
YLegend[cpu]: CPU Load (%)
Legend1[cpu]: 1 Minute Load
Legend2[cpu]: 5 Minute Load
Options[cpu]: growright, nopercent, noinfo

# Memory Usage
Target[mem]: .1.3.6.1.4.1.2021.4.5.0&.1.3.6.1.4.1.2021.4.6.0:${SNMP_COMMUNITY}@127.0.0.1:
Title[mem]: Memory Usage
PageTop[mem]: <h1>System Memory Usage</h1>
MaxBytes[mem]: 100
ShortLegend[mem]: %
YLegend[mem]: Memory (%)
Options[mem]: growright, nopercent

# Disk Usage - Root
Target[disk_root]: .1.3.6.1.4.1.2021.9.1.6.1&.1.3.6.1.4.1.2021.9.1.7.1:${SNMP_COMMUNITY}@127.0.0.1:
Title[disk_root]: Disk Usage - Root Partition
PageTop[disk_root]: <h1>Root Partition Usage</h1>
MaxBytes[disk_root]: 100
ShortLegend[disk_root]: %
YLegend[disk_root]: Disk Usage (%)
Options[disk_root]: growright, nopercent

EOF

    log "SUCCESS" "MRTG configuration generated"
}

generate_template_config() {
    local cfg_file="$1"
    local interfaces=($(detect_network_interfaces))

    log "INFO" "Creating template configuration for ${#interfaces[@]} interfaces"

    cat > "${cfg_file}" << EOF
########################################################################
# MRTG Template Configuration
# Generated by MRTG Professional Suite on $(date)
########################################################################

# Global settings
WorkDir: ${WEB_ROOT}/mrtg
LogDir: ${MRTG_LOG}
Interval: ${INTERVAL:-${DEFAULT_INTERVAL}}
Options[_]: growright, bits
EnableIPv6: yes
Language: english

EOF

    # Add each interface
    for interface in "${interfaces[@]}"; do
        # Try to detect interface speed
        local speed=1000000  # Default 1Gbps
        if [[ -f "/sys/class/net/${interface}/speed" ]]; then
            local detected_speed=$(cat "/sys/class/net/${interface}/speed" 2>/dev/null || echo "1000")
            speed=$((detected_speed * 1000000 / 8))  # Convert to bytes
        fi

        cat >> "${cfg_file}" << EOF
# Interface: ${interface}
Target[${interface}]: ${interface}:${SNMP_COMMUNITY}@127.0.0.1:
MaxBytes[${interface}]: ${speed}
Title[${interface}]: Traffic Analysis for ${interface}
PageTop[${interface}]: <h1>Traffic Analysis for ${interface}</h1>
YLegend[${interface}]: Bits per second
ShortLegend[${interface}]: b/s
Legend1[${interface}]: Incoming Traffic (bits/sec)
Legend2[${interface}]: Outgoing Traffic (bits/sec)
WithPeak[${interface}]: wmy

EOF
    done
}

setup_cron() {
    local interval="${INTERVAL:-${DEFAULT_INTERVAL}}"

    log "INFO" "Setting up cron with ${interval} minute interval..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would add cron job: */${interval} * * * * ${MRTG_BIN}/run-mrtg.sh"
        return 0
    fi

    # Create runner script
    cat > "${MRTG_BIN}/run-mrtg.sh" << EOF
#!/bin/bash
# MRTG Runner Script
# Generated on $(date)

export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Run MRTG (ignore first-run errors)
/usr/bin/mrtg ${MRTG_CONF}/mrtg.cfg --logging ${MRTG_LOG}/mrtg.log 2>/dev/null || true
/usr/bin/mrtg ${MRTG_CONF}/mrtg.cfg --logging ${MRTG_LOG}/mrtg.log 2>/dev/null || true
/usr/bin/mrtg ${MRTG_CONF}/mrtg.cfg --logging ${MRTG_LOG}/mrtg.log

# Generate index
/usr/bin/indexmaker ${MRTG_CONF}/mrtg.cfg --output=${WEB_ROOT}/mrtg/index.html

# Set permissions
chown -R ${WEB_USER}:${WEB_GROUP} ${WEB_ROOT}/mrtg 2>/dev/null || true
chmod -R 755 ${WEB_ROOT}/mrtg 2>/dev/null || true
EOF

    chmod +x "${MRTG_BIN}/run-mrtg.sh"

    # Remove existing MRTG cron entries
    crontab -l 2>/dev/null | grep -v "mrtg" | crontab -

    # Add new cron job with comment for easy identification
    (crontab -l 2>/dev/null; echo "# MRTG Monitoring - Added by MRTG Professional Suite") | crontab -
    (crontab -l 2>/dev/null; echo "*/${interval} * * * * ${MRTG_BIN}/run-mrtg.sh >/dev/null 2>&1") | crontab -

    log "SUCCESS" "Cron job added"
}

setup_web_access() {
    log "INFO" "Setting up web access for existing web server..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure web access for: ${WEB_SERVER}"
        return 0
    fi

    # Create symbolic link if needed
    if [[ "${WEB_ROOT}/mrtg" != "${MRTG_HTML}" ]]; then
        ln -sf "${WEB_ROOT}/mrtg" "${MRTG_HTML}"
    fi

    # Create .htaccess for Apache/LiteSpeed
    if [[ "${WEB_SERVER}" == "apache" ]] || [[ "${WEB_SERVER}" == "litespeed" ]]; then
        cat > "${WEB_ROOT}/mrtg/.htaccess" << EOF
# MRTG Access Control
Order Deny,Allow
Deny from all
Allow from 127.0.0.1
Allow from ::1
# Allow from 192.168.0.0/16  # Uncomment for local network
# Allow from 10.0.0.0/8       # Uncomment for private network
EOF
    fi

    # Create robots.txt
    cat > "${WEB_ROOT}/mrtg/robots.txt" << EOF
User-agent: *
Disallow: /
EOF

    # Set proper permissions
    chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_ROOT}/mrtg" 2>/dev/null || true
    chmod -R 755 "${WEB_ROOT}/mrtg" 2>/dev/null || true

    log "SUCCESS" "Web access configured for ${WEB_SERVER}"
}

configure_panel_integration() {
    local panel=$(detect_control_panel)

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure integration for: ${panel}"
        return 0
    fi

    case "${panel}" in
        "directadmin")
            log "INFO" "Setting up DirectAdmin integration..."
            local da_plugins="/usr/local/directadmin/plugins"
            local mrtg_plugin="${da_plugins}/mrtg-monitor"

            mkdir -p "${mrtg_plugin}/admin"
            mkdir -p "${mrtg_plugin}/data"

            # Create plugin configuration
            cat > "${mrtg_plugin}/plugin.conf" << EOF
name=MRTG Network Monitor
version=1.2
desc=Network traffic monitoring and bandwidth graphing
url=/plugins/mrtg-monitor/admin/
icon=graph
level=admin
EOF

            # Create admin page
            cat > "${mrtg_plugin}/admin/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>MRTG Network Monitor</title>
    <meta http-equiv="refresh" content="300">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 10px; margin-bottom: 20px; }
        .graph-container { margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Traffic Monitoring</h1>
        <p>DirectAdmin Integration by Wael Isa</p>
    </div>
    <div class="graph-container">
        <iframe src="/mrtg/" width="100%" height="1000" frameborder="0"></iframe>
    </div>
</body>
</html>
EOF

            # Set proper ownership
            chown -R diradmin:diradmin "${mrtg_plugin}" 2>/dev/null || true
            log "SUCCESS" "DirectAdmin integration configured"
            ;;

        "cpanel")
            log "INFO" "cPanel detected - creating symlink in cpanel's webroot"
            if [[ -d "/usr/local/apache/htdocs" ]]; then
                ln -sf "${WEB_ROOT}/mrtg" "/usr/local/apache/htdocs/mrtg"
            fi
            log "SUCCESS" "cPanel integration configured"
            ;;

        "plesk")
            log "INFO" "Plesk detected - adding to vhosts"
            # Plesk usually uses /var/www/vhosts/domain.com/httpdocs
            # We'll create a symlink in the default domain
            if [[ -d "/var/www/vhosts/default/htdocs" ]]; then
                ln -sf "${WEB_ROOT}/mrtg" "/var/www/vhosts/default/htdocs/mrtg"
            fi
            log "SUCCESS" "Plesk integration configured"
            ;;
    esac
}

# =============================================================================
# INITIALIZATION FUNCTIONS
# =============================================================================

initialize_mrtg() {
    log "INFO" "Running initial MRTG collection (3-pass warmup)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would run MRTG 3 times to initialize data"
        return 0
    fi

    local mrtg_path=$(command -v mrtg || echo "/usr/bin/mrtg")
    local cfg_file="${MRTG_CONF}/mrtg.cfg"

    # Run MRTG 3 times (required for first-time setup)
    for i in {1..3}; do
        log "INFO" "MRTG pass ${i}/3..."
        env LANG=C ${mrtg_path} "${cfg_file}" --logging "${MRTG_LOG}/mrtg.log" >/dev/null 2>&1 || true
    done

    # Generate index page
    local indexmaker_path=$(command -v indexmaker || echo "/usr/bin/indexmaker")
    ${indexmaker_path} "${cfg_file}" --output="${WEB_ROOT}/mrtg/index.html"

    # Set permissions
    chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_ROOT}/mrtg" 2>/dev/null || true
    chmod -R 755 "${WEB_ROOT}/mrtg" 2>/dev/null || true

    log "SUCCESS" "Initial MRTG data collection complete"
}

# =============================================================================
# BACKUP FUNCTIONS
# =============================================================================

backup_config() {
    local backup_file="${CONFIG_BACKUP_DIR}/mrtg-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

    log "INFO" "Creating backup: ${backup_file}"

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would backup configuration to: ${backup_file}"
        return 0
    fi

    tar -czf "${backup_file}" \
        --exclude="${MRTG_LOG}/*" \
        --exclude="${MRTG_VAR}/*" \
        "${MRTG_CONF}" 2>/dev/null || true

    # Backup SNMP config
    if [[ -f /etc/snmp/snmpd.conf ]]; then
        cp /etc/snmp/snmpd.conf "${CONFIG_BACKUP_DIR}/snmpd.conf.backup.$(date +%Y%m%d)"
    fi

    log "SUCCESS" "Backup created: ${backup_file}"
    echo -e "${GREEN}Backup saved to: ${backup_file}${NC}"
}

# =============================================================================
# UNINSTALL FUNCTIONS
# =============================================================================

uninstall_mrtg() {
    log "INFO" "Starting uninstallation process..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would perform complete uninstall"
        return 0
    fi

    # Confirm uninstall
    if ! confirm_action "Are you sure you want to completely uninstall MRTG?"; then
        log "INFO" "Uninstall cancelled"
        return 0
    fi

    # Create backup before uninstall
    backup_config

    # Remove cron jobs
    log "INFO" "Removing cron jobs..."
    crontab -l 2>/dev/null | grep -v "mrtg" | crontab -

    # Ask about removing packages
    if confirm_action "Do you want to remove MRTG and SNMP packages?"; then
        log "INFO" "Removing packages..."
        case "${OS_ID}" in
            ubuntu|debian)
                apt-get remove --purge -y mrtg snmpd snmp
                ;;
            centos|rhel|almalinux|rocky|fedora)
                yum remove -y mrtg net-snmp net-snmp-utils
                ;;
        esac
    fi

    # Ask about removing data
    if confirm_action "Do you want to remove all MRTG data and configurations?"; then
        log "INFO" "Removing MRTG files..."
        rm -rf "${MRTG_BASE}"
        rm -rf "${MRTG_VAR}"
        rm -rf "${WEB_ROOT}/mrtg"
        rm -rf "/usr/local/directadmin/plugins/mrtg-monitor" 2>/dev/null || true
        log "INFO" "All MRTG data removed"
    fi

    # Restore original SNMP config if exists
    if [[ -f /etc/snmp/snmpd.conf.backup.* ]] && confirm_action "Restore original SNMP configuration?"; then
        cp /etc/snmp/snmpd.conf.backup.* /etc/snmp/snmpd.conf
        systemctl restart snmpd
    fi

    log "SUCCESS" "Uninstall completed"
}

# =============================================================================
# STATUS FUNCTIONS
# =============================================================================

check_status() {
    echo -e "\n${BOLD}=== MRTG Installation Status ===${NC}\n"

    # Check if installed
    if [[ -d "${MRTG_BASE}" ]] && [[ -f "${MRTG_CONF}/mrtg.cfg" ]]; then
        echo -e "  ${GREEN}✓${NC} MRTG installed"
    else
        echo -e "  ${RED}✗${NC} MRTG not installed"
    fi

    # Check services
    if systemctl is-active --quiet snmpd 2>/dev/null || service snmpd status 2>/dev/null | grep -q "running"; then
        echo -e "  ${GREEN}✓${NC} SNMP service running"
    else
        echo -e "  ${RED}✗${NC} SNMP service not running"
    fi

    # Check web server
    echo -e "  ${GREEN}✓${NC} Web server: ${WEB_SERVER} (user: ${WEB_USER})"

    # Check cron
    if crontab -l 2>/dev/null | grep -q "mrtg"; then
        local interval=$(crontab -l | grep "mrtg" | grep -v "^#" | awk '{print $2}')
        echo -e "  ${GREEN}✓${NC} Cron job active (interval: ${interval} minutes)"
    else
        echo -e "  ${RED}✗${NC} No cron job found"
    fi

    # Check web interface
    if [[ -f "${WEB_ROOT}/mrtg/index.html" ]]; then
        echo -e "  ${GREEN}✓${NC} Web interface accessible at: ${WEB_ROOT}/mrtg/"
        # Try to get server IP
        local server_ip=$(ip route get 1 | awk '{print $NF;exit}' 2>/dev/null || echo "your-server")
        echo -e "  ${CYAN}   URL: http://${server_ip}/mrtg/${NC}"
    else
        echo -e "  ${RED}✗${NC} Web interface not generated yet"
    fi

    # Check interfaces
    local interfaces=($(detect_network_interfaces))
    echo -e "\n${BOLD}=== Monitored Interfaces (${#interfaces[@]}) ===${NC}\n"
    for interface in "${interfaces[@]}"; do
        if [[ -f "${WEB_ROOT}/mrtg/${interface}.html" ]]; then
            echo -e "  ${GREEN}✓${NC} ${interface} - monitoring active"
        else
            echo -e "  ${YELLOW}○${NC} ${interface} - waiting for data"
        fi
    done

    # Last run time
    if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
        echo -e "\n${BOLD}=== Last Activity ===${NC}\n"
        echo -e "  Last log entry: $(tail -1 "${MRTG_LOG}/mrtg.log" | cut -c1-80)"
    fi
    echo ""
}

# =============================================================================
# INSTALLATION WIZARD
# =============================================================================

installation_wizard() {
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
    ${BOLD}Professional Monitoring Suite${NC}
    Version: ${SCRIPT_VERSION} | Author: ${SCRIPT_AUTHOR}
    GitHub: ${SCRIPT_URL}
================================================================================
EOF

    echo -e "\n${YELLOW}This installer will NOT modify your web server configuration${NC}"
    echo -e "${YELLOW}It will detect and use your existing setup${NC}\n"

    # Check root
    check_root

    # Detect OS and web server
    detect_os
    detect_web_server || error_exit "Web server detection failed"

    # Show detected configuration
    echo -e "\n${BOLD}Detected System Configuration:${NC}"
    echo -e "  OS: ${GREEN}${OS} ${VER}${NC}"
    echo -e "  Web Server: ${GREEN}${WEB_SERVER}${NC}"
    echo -e "  Web User: ${GREEN}${WEB_USER}${NC}"
    echo -e "  Web Root: ${GREEN}${WEB_ROOT}${NC}"

    local panel=$(detect_control_panel)
    if [[ "${panel}" != "none" ]]; then
        echo -e "  Control Panel: ${GREEN}${panel}${NC}"
    fi

    # Get installation parameters
    echo -e "\n${BOLD}Configuration Options:${NC}"
    read -p "Monitoring interval in minutes [${DEFAULT_INTERVAL}]: " interval
    interval=${interval:-${DEFAULT_INTERVAL}}

    read -p "SNMP Community String [auto-generate]: " snmp_community
    SNMP_COMMUNITY=${snmp_community}

    read -p "Notification email [${DEFAULT_EMAIL}]: " email
    DEFAULT_EMAIL=${email:-${DEFAULT_EMAIL}}

    # Confirm installation
    echo -e "\n${YELLOW}Installation Summary:${NC}"
    echo "  Interval: ${interval} minutes"
    echo "  SNMP Community: ${SNMP_COMMUNITY:-"<auto-generated>"}"
    echo "  Email: ${DEFAULT_EMAIL}"
    echo "  Web Directory: ${WEB_ROOT}/mrtg"
    echo ""

    if ! confirm_action "Proceed with installation?"; then
        log "INFO" "Installation cancelled"
        return 0
    fi

    # Set interval
    INTERVAL=${interval}

    # Perform installation
    log "INFO" "Starting installation..."

    install_dependencies
    create_directories
    configure_snmp
    configure_firewall
    generate_mrtg_config
    setup_web_access
    configure_panel_integration
    setup_cron
    initialize_mrtg

    # Save configuration for uninstall
    cat > "${MRTG_CONF}/install.conf" << EOF
# MRTG Installation Configuration
WEB_ROOT="${WEB_ROOT}"
WEB_USER="${WEB_USER}"
WEB_GROUP="${WEB_GROUP}"
SNMP_COMMUNITY="${SNMP_COMMUNITY}"
INSTALL_DATE="$(date)"
EOF

    log "SUCCESS" "Installation completed successfully!"

    # Show next steps
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Installation Complete!${NC}"
    echo -e "${GREEN}========================================${NC}\n"

    echo -e "Access MRTG at: ${BLUE}http://$(ip route get 1 | awk '{print $NF;exit}' 2>/dev/null || echo "your-server")/mrtg/${NC}"
    echo -e "Configuration: ${CYAN}${MRTG_CONF}/mrtg.cfg${NC}"
    echo -e "SNMP Community: ${YELLOW}${SNMP_COMMUNITY}${NC} ${RED}(keep this secure!)${NC}"
    echo -e "Logs: ${CYAN}${MRTG_LOG}${NC}"
    echo -e "\nTo uninstall: ${CYAN}$0 --uninstall${NC}\n"

    check_status
}

# =============================================================================
# MAIN MENU
# =============================================================================

show_menu() {
    clear
    cat << "EOF"
================================================================================
    MRTG Professional Monitoring Suite - Enterprise Edition
================================================================================
EOF
    echo -e "\n${BOLD}MAIN MENU${NC}\n"

    echo -e "  ${GREEN}1)${NC} Install MRTG (Full installation wizard)"
    echo -e "  ${GREEN}2)${NC} Uninstall MRTG"
    echo -e "  ${GREEN}3)${NC} Add/Update Cron Job"
    echo -e "  ${GREEN}4)${NC} Remove Cron Job"
    echo -e "  ${GREEN}5)${NC} Backup Configuration"
    echo -e "  ${GREEN}6)${NC} Check Status"
    echo -e "  ${GREEN}7)${NC} Test Configuration"
    echo -e "  ${GREEN}8)${NC} View Logs"
    echo -e "  ${GREEN}9)${NC} Regenerate Index Page"
    echo -e "  ${GREEN}10)${NC} Dry Run (Test without changes)"
    echo -e "  ${GREEN}0)${NC} Exit\n"

    read -p "Enter your choice [0-10]: " choice

    case ${choice} in
        1) installation_wizard ;;
        2) uninstall_mrtg ;;
        3) setup_cron ;;
        4)
            if confirm_action "Remove MRTG cron job?"; then
                crontab -l 2>/dev/null | grep -v "mrtg" | crontab -
                log "SUCCESS" "Cron job removed"
            fi
            ;;
        5) backup_config ;;
        6) check_status ;;
        7)
            log "INFO" "Testing MRTG configuration..."
            if [[ -f "${MRTG_CONF}/mrtg.cfg" ]]; then
                env LANG=C mrtg "${MRTG_CONF}/mrtg.cfg" --check
            else
                log "ERROR" "Configuration not found"
            fi
            ;;
        8)
            if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
                tail -50 "${MRTG_LOG}/mrtg.log"
            else
                log "ERROR" "Log file not found"
            fi
            ;;
        9)
            if [[ -f "${MRTG_CONF}/mrtg.cfg" ]]; then
                indexmaker "${MRTG_CONF}/mrtg.cfg" --output="${WEB_ROOT}/mrtg/index.html"
                log "SUCCESS" "Index page regenerated"
            fi
            ;;
        10)
            DRY_RUN=true
            log "INFO" "Running in DRY RUN mode - no changes will be made"
            installation_wizard
            DRY_RUN=false
            ;;
        0)
            echo -e "\n${GREEN}Thank you for using MRTG Professional Suite!${NC}"
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
# COMMAND LINE ARGUMENTS
# =============================================================================

print_help() {
    cat << EOF
${BOLD}NAME${NC}
    install-mrtg.sh - MRTG Professional Monitoring Suite

${BOLD}SYNOPSIS${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS${NC}
    --help, -h              Show this help message
    --install, -i           Run installation wizard
    --uninstall, -u         Complete uninstall MRTG
    --dry-run               Test installation without making changes
    --status, -s            Check MRTG status
    --backup, -b            Backup configuration
    --version, -v           Show version

${BOLD}EXAMPLES${NC}
    $0 --install            # Interactive installation
    $0 --dry-run            # Test without changes
    $0 --uninstall          # Remove MRTG
    $0 --status             # Check status

${BOLD}AUTHOR${NC}
    Written by ${SCRIPT_AUTHOR} <${SCRIPT_URL}>
EOF
}

main() {
    # Create log file
    touch "${LOG_FILE}"
    chmod 644 "${LOG_FILE}"

    # Parse arguments
    if [[ $# -gt 0 ]]; then
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
                uninstall_mrtg
                exit 0
                ;;
            --dry-run)
                check_root
                DRY_RUN=true
                installation_wizard
                exit 0
                ;;
            --status|-s)
                check_root
                detect_web_server
                check_status
                exit 0
                ;;
            --backup|-b)
                check_root
                backup_config
                exit 0
                ;;
            --version|-v)
                echo "MRTG Professional Suite ${SCRIPT_VERSION}"
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                print_help
                exit 1
                ;;
        esac
    else
        # Interactive menu
        show_menu
    fi
}

# Trap errors
trap 'error_exit "Error on line $LINENO"' ERR

# Run main function
main "$@"
