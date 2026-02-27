#!/bin/bash
#
# MRTG Professional Monitoring Suite - Enterprise Edition v1.3.0
# Ultra-reliable, production-hardened monitoring for hosting environments
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
# GitHub:      https://github.com/waelisa/mrtg
# Version:     v1.3.0
# Build Date:  02/27/2026
# License:     MIT
#
# DESCRIPTION:
#   Enterprise-grade MRTG installer that WORKS with ANY existing setup
#   - Zero assumptions about web server configuration
#   - Intelligent detection of running services
#   - Safe firewall configuration (CSF/firewalld/UFW/iptables)
#   - Complete uninstall with rollback capability
#   - Self-healing health checks
#   - Dry-run mode for testing
#
# USAGE:
#   ./install-mrtg.sh [OPTIONS]
#
# OPTIONS:
#   --install, -i     Run installation wizard
#   --uninstall, -u   Complete removal with backup
#   --status, -s      Full system health check
#   --repair, -r      Attempt to repair broken installation
#   --backup, -b      Backup current configuration
#   --restore, -R     Restore from backup
#   --dry-run         Test without making changes
#   --force           Skip confirmations (use with caution)
#   --help, -h        Show this help message
#
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# GLOBAL CONSTANTS
# =============================================================================

readonly SCRIPT_VERSION="v1.3.0"
readonly SCRIPT_AUTHOR="Wael Isa"
readonly SCRIPT_URL="https://github.com/waelisa/mrtg"
readonly LOG_FILE="/var/log/mrtg-installer.log"
readonly BACKUP_DIR="/root/mrtg-backups"
readonly LOCK_FILE="/var/run/mrtg-installer.lock"
readonly SCRIPT_NAME=$(basename "$0")

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Installation paths
MRTG_BASE="/usr/local/mrtg"
MRTG_CONF="${MRTG_BASE}/conf"
MRTG_LOG="${MRTG_BASE}/logs"
MRTG_HTML="${MRTG_BASE}/html"
MRTG_BIN="${MRTG_BASE}/bin"
MRTG_VAR="/var/lib/mrtg"

# Default values
DEFAULT_INTERVAL=5
DEFAULT_EMAIL="root@localhost"
SNMP_COMMUNITY=""
WEB_ROOT=""
WEB_USER=""
WEB_GROUP=""
WEB_SERVER="unknown"
INTERVAL=${DEFAULT_INTERVAL}
FORCE_MODE=false
DRY_RUN=false

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Always log to file
    echo -e "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"

    # Console output with colors (skip in dry-run unless error)
    if [[ "${DRY_RUN}" == true && "${level}" != "ERROR" ]]; then
        echo -e "${YELLOW}[DRY RUN]${NC} ${message}"
    else
        case "${level}" in
            "ERROR")   echo -e "${RED}[ERROR]${NC} ${message}" >&2 ;;
            "WARNING") echo -e "${YELLOW}[WARNING]${NC} ${message}" ;;
            "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} ${message}" ;;
            "INFO")    echo -e "${CYAN}[INFO]${NC} ${message}" ;;
            "DEBUG")   [[ -n "${DEBUG}" ]] && echo -e "${MAGENTA}[DEBUG]${NC} ${message}" ;;
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
        error_exit "This script must be run as root. Use: sudo ${SCRIPT_NAME}"
    fi
}

confirm_action() {
    local prompt="$1"
    local default="${2:-N}"

    if [[ "${FORCE_MODE}" == true ]] || [[ "${DRY_RUN}" == true ]]; then
        return 0
    fi

    local response
    read -p "${prompt} (y/N): " response
    [[ "${response}" =~ ^[Yy]$ ]]
}

acquire_lock() {
    if [[ -f "${LOCK_FILE}" ]]; then
        local pid=$(cat "${LOCK_FILE}")
        if kill -0 "${pid}" 2>/dev/null; then
            error_exit "Another instance of ${SCRIPT_NAME} is running (PID: ${pid})"
        else
            log "WARNING" "Removing stale lock file"
            rm -f "${LOCK_FILE}"
        fi
    fi
    echo $$ > "${LOCK_FILE}"
    trap 'rm -f "${LOCK_FILE}"' EXIT
}

cleanup() {
    rm -f "${LOCK_FILE}" 2>/dev/null || true
}

# =============================================================================
# ENHANCED DETECTION FUNCTIONS
# =============================================================================

detect_os() {
    log "INFO" "Detecting operating system..."

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="${NAME}"
        OS_VERSION="${VERSION_ID}"
        OS_ID="${ID}"
        OS_ID_LIKE="${ID_LIKE:-}"
    elif [[ -f /etc/debian_version ]]; then
        OS_NAME="Debian"
        OS_VERSION=$(cat /etc/debian_version)
        OS_ID="debian"
        OS_ID_LIKE="debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS_NAME="RedHat"
        OS_VERSION=$(rpm -q --qf "%{VERSION}" $(rpm -q --whatprovides redhat-release) 2>/dev/null || echo "unknown")
        OS_ID="rhel"
        OS_ID_LIKE="rhel"
    else
        error_exit "Unsupported operating system"
    fi

    log "SUCCESS" "Detected: ${OS_NAME} ${OS_VERSION} (${OS_ID})"
}

detect_control_panel() {
    PANEL_TYPE="none"

    # DirectAdmin
    if [[ -d /usr/local/directadmin ]]; then
        PANEL_TYPE="directadmin"
        if [[ -f /usr/local/directadmin/conf/directadmin.conf ]]; then
            PANEL_VERSION=$(grep -i version /usr/local/directadmin/conf/directadmin.conf | cut -d= -f2 | tr -d ' ')
        fi
        log "SUCCESS" "DirectAdmin detected (Version: ${PANEL_VERSION:-unknown})"

    # cPanel
    elif [[ -d /usr/local/cpanel ]]; then
        PANEL_TYPE="cpanel"
        if command -v /usr/local/cpanel/cpanel >/dev/null; then
            PANEL_VERSION=$(/usr/local/cpanel/cpanel -V 2>/dev/null || echo "unknown")
        fi
        log "SUCCESS" "cPanel detected (Version: ${PANEL_VERSION:-unknown})"

    # Plesk
    elif [[ -d /usr/local/psa ]]; then
        PANEL_TYPE="plesk"
        if command -v plesk >/dev/null; then
            PANEL_VERSION=$(plesk version 2>/dev/null | head -1 | awk '{print $2}')
        fi
        log "SUCCESS" "Plesk detected (Version: ${PANEL_VERSION:-unknown})"

    # ISPConfig
    elif [[ -d /usr/local/ispconfig ]]; then
        PANEL_TYPE="ispconfig"
        log "SUCCESS" "ISPConfig detected"

    # Vestacp
    elif [[ -d /usr/local/vesta ]]; then
        PANEL_TYPE="vestacp"
        log "SUCCESS" "VestaCP detected"

    # Webmin/Virtualmin
    elif [[ -d /usr/share/webmin ]]; then
        PANEL_TYPE="webmin"
        log "SUCCESS" "Webmin detected"
    fi
}

detect_web_server() {
    log "INFO" "Detecting active web server..."

    local web_servers_found=()

    # Check for running processes (most reliable)
    if pgrep -x "nginx" >/dev/null 2>&1; then
        WEB_SERVER="nginx"
        WEB_USER=$(ps aux | grep nginx | grep -v grep | head -1 | awk '{print $1}' || echo "www-data")
        WEB_GROUP=$(id -gn "${WEB_USER}" 2>/dev/null || echo "www-data")
        web_servers_found+=("nginx (active)")
    fi

    if pgrep -x "httpd" >/dev/null 2>&1 || pgrep -x "apache2" >/dev/null 2>&1; then
        WEB_SERVER="apache"
        if [[ -f /etc/redhat-release ]]; then
            WEB_USER="apache"
            WEB_GROUP="apache"
        else
            WEB_USER="www-data"
            WEB_GROUP="www-data"
        fi
        web_servers_found+=("apache (active)")
    fi

    if pgrep -x "litespeed" >/dev/null 2>&1 || pgrep -x "lshttpd" >/dev/null 2>&1; then
        WEB_SERVER="litespeed"
        WEB_USER="nobody"
        WEB_GROUP="nobody"
        web_servers_found+=("litespeed (active)")
    fi

    if pgrep -x "caddy" >/dev/null 2>&1; then
        WEB_SERVER="caddy"
        WEB_USER=$(ps aux | grep caddy | grep -v grep | head -1 | awk '{print $1}' || echo "caddy")
        WEB_GROUP=$(id -gn "${WEB_USER}" 2>/dev/null || echo "caddy")
        web_servers_found+=("caddy (active)")
    fi

    if pgrep -x "openlitespeed" >/dev/null 2>&1; then
        WEB_SERVER="openlitespeed"
        WEB_USER="nobody"
        WEB_GROUP="nobody"
        web_servers_found+=("openlitespeed (active)")
    fi

    # If multiple web servers found, prioritize
    if [[ ${#web_servers_found[@]} -gt 1 ]]; then
        log "WARNING" "Multiple web servers detected: ${web_servers_found[*]}"
        # Prioritize nginx > apache > litespeed
        for server in nginx apache litespeed openlitespeed caddy; do
            if [[ " ${web_servers_found[*]} " =~ ${server} ]]; then
                WEB_SERVER="${server}"
                log "INFO" "Prioritizing: ${WEB_SERVER}"
                break
            fi
        done
    elif [[ ${#web_servers_found[@]} -eq 0 ]]; then
        # No running server, check installed
        if command -v nginx >/dev/null 2>&1; then
            WEB_SERVER="nginx"
            WEB_USER="www-data"
            WEB_GROUP="www-data"
            log "WARNING" "Nginx installed but not running"
        elif command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
            WEB_SERVER="apache"
            WEB_USER=$([[ -f /etc/redhat-release ]] && echo "apache" || echo "www-data")
            WEB_GROUP=$([[ -f /etc/redhat-release ]] && echo "apache" || echo "www-data")
            log "WARNING" "Apache installed but not running"
        else
            error_exit "No supported web server detected. Please install nginx, apache, or litespeed first."
        fi
    fi

    # Detect web root
    detect_web_root

    log "SUCCESS" "Web server: ${WEB_SERVER} (User: ${WEB_USER}, Group: ${WEB_GROUP})"
}

detect_web_root() {
    # Panel-specific roots
    case "${PANEL_TYPE}" in
        "directadmin")
            if [[ -d "/var/www/html" ]]; then
                WEB_ROOT="/var/www/html"
            elif [[ -d "/home/*/domains" ]]; then
                WEB_ROOT="/var/www/html"  # fallback
            fi
            ;;
        "cpanel")
            if [[ -d "/usr/local/apache/htdocs" ]]; then
                WEB_ROOT="/usr/local/apache/htdocs"
            elif [[ -d "/home/*/public_html" ]]; then
                # Use first user's public_html as fallback
                WEB_ROOT="/usr/local/apache/htdocs"
            fi
            ;;
        "plesk")
            if [[ -d "/var/www/vhosts/default/htdocs" ]]; then
                WEB_ROOT="/var/www/vhosts/default/htdocs"
            else
                WEB_ROOT="/var/www/vhosts"
            fi
            ;;
        *)
            # Generic web roots
            local common_roots=(
                "/var/www/html"
                "/var/www"
                "/usr/share/nginx/html"
                "/srv/www/htdocs"
                "/usr/local/www"
                "/home/www"
                "/var/www/htdocs"
            )

            for root in "${common_roots[@]}"; do
                if [[ -d "${root}" ]]; then
                    WEB_ROOT="${root}"
                    break
                fi
            done
            ;;
    esac

    # Create web root if it doesn't exist
    if [[ -z "${WEB_ROOT}" ]] || [[ ! -d "${WEB_ROOT}" ]]; then
        WEB_ROOT="/var/www/html"
        log "WARNING" "Creating web root: ${WEB_ROOT}"
        mkdir -p "${WEB_ROOT}"
    fi

    # Verify writability
    if [[ ! -w "${WEB_ROOT}" ]]; then
        log "WARNING" "Web root ${WEB_ROOT} is not writable. Check permissions."
    fi
}

detect_network_interfaces() {
    local interfaces=()

    # Get all active network interfaces (with IP)
    while IFS= read -r interface; do
        # Skip loopback, virtual, and docker interfaces
        if [[ ! "${interface}" =~ ^(lo|virbr|docker|veth|br-|tun) ]] && \
           ip link show "${interface}" 2>/dev/null | grep -q "UP"; then
            interfaces+=("${interface}")
        fi
    done < <(ls /sys/class/net/ 2>/dev/null || ip link show | awk -F': ' '/^[0-9]+: / {print $2}' | cut -d@ -f1)

    # Fallback to all interfaces except loopback
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        while IFS= read -r interface; do
            if [[ "${interface}" != "lo" ]]; then
                interfaces+=("${interface}")
            fi
        done < <(ls /sys/class/net/ 2>/dev/null)
    fi

    printf '%s\n' "${interfaces[@]}"
}

detect_ip_address() {
    local ip=""

    # Try multiple methods
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip route get 1 2>/dev/null | awk '{print $NF;exit}' 2>/dev/null)
    fi

    if [[ -z "${ip}" ]] && command -v curl >/dev/null 2>&1; then
        ip=$(curl -s --max-time 2 ifconfig.me 2>/dev/null || echo "")
    fi

    if [[ -z "${ip}" ]] && command -v wget >/dev/null 2>&1; then
        ip=$(wget -qO- --timeout=2 ifconfig.me 2>/dev/null || echo "")
    fi

    echo "${ip:-localhost}"
}

# =============================================================================
# ENHANCED INSTALLATION FUNCTIONS
# =============================================================================

install_dependencies() {
    log "INFO" "Installing MRTG and SNMP packages (no web server)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would install: mrtg, snmpd, snmp, perl modules"
        return 0
    fi

    case "${OS_ID}" in
        ubuntu|debian)
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                mrtg \
                snmpd \
                snmp \
                libsnmp-dev \
                perl \
                libwww-perl \
                libcrypt-ssleay-perl \
                libdigest-hmac-perl \
                libio-socket-ssl-perl \
                libnet-snmp-perl \
                openssl \
                ca-certificates \
                --no-install-recommends
            ;;
        centos|rhel|almalinux|rocky|fedora)
            # Enable EPEL if needed
            if [[ "${OS_ID}" != "fedora" ]] && ! rpm -q epel-release >/dev/null 2>&1; then
                yum install -y -q epel-release
            fi
            yum install -y -q \
                mrtg \
                net-snmp \
                net-snmp-utils \
                net-snmp-devel \
                perl-libwww-perl \
                perl-Crypt-SSLeay \
                perl-Digest-HMAC \
                perl-IO-Socket-SSL \
                perl-Net-SNMP \
                openssl \
                ca-certificates
            ;;
        *)
            error_exit "Unsupported OS for package installation: ${OS_ID}"
            ;;
    esac

    # Verify installations
    for cmd in mrtg snmpd cfgmaker indexmaker; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            log "WARNING" "${cmd} not found in PATH"
        else
            log "DEBUG" "${cmd} found at $(command -v "${cmd}")"
        fi
    done

    log "SUCCESS" "Dependencies installed"
}

configure_snmp() {
    log "INFO" "Configuring SNMP..."

    # Generate secure community string if not set
    if [[ -z "${SNMP_COMMUNITY}" ]]; then
        if command -v openssl >/dev/null 2>&1; then
            SNMP_COMMUNITY="mrtg_$(openssl rand -hex 8)"
        else
            SNMP_COMMUNITY="mrtg_$(date +%s | sha256sum | base64 | head -c 16)"
        fi
        log "INFO" "Generated secure community: ${SNMP_COMMUNITY}"
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure SNMP with community: ${SNMP_COMMUNITY}"
        return 0
    fi

    # Backup existing config
    if [[ -f /etc/snmp/snmpd.conf ]]; then
        cp /etc/snmp/snmpd.conf "/etc/snmp/snmpd.conf.backup.$(date +%Y%m%d-%H%M%S)"
    fi

    # Create secure SNMP configuration
    cat > /etc/snmp/snmpd.conf << EOF
########################################################################
# SNMPd Configuration for MRTG
# Generated: $(date)
# Community: ${SNMP_COMMUNITY}
########################################################################

# Listen only on localhost for security
agentAddress udp:127.0.0.1:161

# Read-only access with custom community
rocommunity ${SNMP_COMMUNITY} 127.0.0.1
rocommunity6 ${SNMP_COMMUNITY} ::1

# System information
syslocation "Production Server"
syscontact ${DEFAULT_EMAIL}
sysservices 0

# Process monitoring
proc  httpd 10 5
proc  nginx 10 5
proc  mysqld 10 5
proc  sshd
proc  snmpd

# Disk monitoring
includeAllDisks 10%

# Load averages
load 12 10 5

# Network interfaces
interface eth0
interface lo

# View definitions
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.2
view   systemonly  included   .1.3.6.1.2.1.3
view   all         included   .1                               80

# Access control
access  MyROGroup   ""         any       noauth    exact   all    none   none

# Disable default community
com2sec paranoid default public
group paranoid v1 paranoid
group paranoid v2c paranoid
access paranoid "" any noauth exact system none none

EOF

    # Fix permissions
    chmod 600 /etc/snmp/snmpd.conf

    # Handle systemd vs init
    if systemctl list-units --full -all 2>/dev/null | grep -q 'snmpd.service'; then
        systemctl unmask snmpd >/dev/null 2>&1 || true
        systemctl enable snmpd >/dev/null 2>&1 || true
        systemctl restart snmpd
    else
        service snmpd restart
    fi

    # Wait for SNMP to fully start
    log "INFO" "Waiting for SNMP to initialize..."
    sleep 5

    # Verify SNMP is responding
    if command -v snmpwalk >/dev/null 2>&1; then
        if snmpwalk -v 2c -c "${SNMP_COMMUNITY}" -t 2 127.0.0.1 system 2>/dev/null | grep -q "sysName"; then
            log "SUCCESS" "SNMP responding correctly"
        else
            log "WARNING" "SNMP not responding. Check configuration."
        fi
    fi

    log "SUCCESS" "SNMP configured"
}

configure_firewall() {
    log "INFO" "Configuring firewall for SNMP (UDP 161)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure firewall for SNMP"
        return 0
    fi

    local firewall_configured=false

    # CSF (ConfigServer Firewall) - Most common in hosting
    if [[ -f /etc/csf/csf.conf ]]; then
        log "INFO" "CSF firewall detected"

        # Backup CSF config
        cp /etc/csf/csf.conf "/etc/csf/csf.conf.backup.$(date +%Y%m%d)"

        # Safely add UDP ports
        for port_type in UDP_IN UDP_OUT; do
            local current_value=$(grep "^${port_type} =" /etc/csf/csf.conf | cut -d'"' -f2)

            if [[ -z "${current_value}" ]]; then
                # Empty string case
                sed -i "s/^${port_type} = \"\"/${port_type} = \"161\"/" /etc/csf/csf.conf
                log "INFO" "Set ${port_type} to \"161\""
            elif ! echo "${current_value}" | grep -q "161"; then
                # Add to existing list
                sed -i "s/^${port_type} = \"${current_value}\"/${port_type} = \"${current_value},161\"/" /etc/csf/csf.conf
                log "INFO" "Added 161 to ${port_type}"
            fi
        done

        # Restart CSF
        csf -r >/dev/null 2>&1
        firewall_configured=true
        log "SUCCESS" "CSF configured for SNMP"
    fi

    # Firewalld
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log "INFO" "Firewalld detected"
        firewall-cmd --permanent --add-service=snmp
        firewall-cmd --reload >/dev/null
        firewall_configured=true
        log "SUCCESS" "Firewalld configured for SNMP"
    fi

    # UFW
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
        log "INFO" "UFW detected"
        ufw allow snmp >/dev/null 2>&1
        firewall_configured=true
        log "SUCCESS" "UFW configured for SNMP"
    fi

    # iptables (fallback)
    if [[ "${firewall_configured}" == false ]] && command -v iptables >/dev/null 2>&1; then
        log "INFO" "Configuring iptables for SNMP"

        # Check if rules already exist
        if ! iptables -C INPUT -p udp --dport 161 -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p udp --dport 161 -s 127.0.0.1 -j ACCEPT
            iptables -A INPUT -p udp --dport 161 -m state --state NEW -j ACCEPT
            log "SUCCESS" "iptables rules added"

            # Save rules based on OS
            if [[ -f /etc/redhat-release ]]; then
                service iptables save >/dev/null 2>&1 || true
            elif [[ -f /etc/debian_version ]]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            fi
        fi
    fi

    if [[ "${firewall_configured}" == false ]]; then
        log "INFO" "No active firewall detected"
    fi
}

create_directories() {
    log "INFO" "Creating directory structure..."

    local dirs=(
        "${MRTG_BASE}"
        "${MRTG_CONF}"
        "${MRTG_LOG}"
        "${MRTG_HTML}"
        "${MRTG_BIN}"
        "${MRTG_VAR}"
        "${BACKUP_DIR}"
        "${WEB_ROOT}/mrtg"
    )

    for dir in "${dirs[@]}"; do
        if [[ ! -d "${dir}" ]]; then
            if [[ "${DRY_RUN}" == true ]]; then
                log "INFO" "Would create directory: ${dir}"
            else
                mkdir -p "${dir}"
                log "DEBUG" "Created: ${dir}"
            fi
        fi
    done

    if [[ "${DRY_RUN}" != true ]]; then
        # Set secure permissions
        chmod 755 "${MRTG_BASE}"
        chmod 750 "${MRTG_CONF}"
        chmod 755 "${MRTG_LOG}"
        chmod 755 "${MRTG_HTML}"
        chmod 755 "${WEB_ROOT}/mrtg"
    fi

    log "SUCCESS" "Directories created"
}

generate_mrtg_config() {
    log "INFO" "Generating MRTG configuration..."

    local cfg_file="${MRTG_CONF}/mrtg.cfg"
    local mrtg_path=$(command -v mrtg || echo "/usr/bin/mrtg")
    local cfgmaker_path=$(command -v cfgmaker || echo "/usr/bin/cfgmaker")
    local indexmaker_path=$(command -v indexmaker || echo "/usr/bin/indexmaker")

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would generate config using: ${cfgmaker_path}"
        return 0
    fi

    # Wait for SNMP to be ready
    local max_attempts=10
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if snmpget -v 2c -c "${SNMP_COMMUNITY}" -t 1 127.0.0.1 sysUpTime.0 >/dev/null 2>&1; then
            log "INFO" "SNMP ready after ${attempt} seconds"
            break
        fi
        log "DEBUG" "Waiting for SNMP (${attempt}/${max_attempts})..."
        sleep 1
        ((attempt++))
    done

    # Use cfgmaker with timeout and retry
    local cfg_success=false
    for i in {1..3}; do
        log "INFO" "Attempt ${i} to generate configuration..."
        if timeout 30 ${cfgmaker_path} \
            --global "WorkDir: ${WEB_ROOT}/mrtg" \
            --global "Options[_]: growright, bits, nopercent" \
            --global "LogDir: ${MRTG_LOG}" \
            --global "RunAsDaemon: No" \
            --global "Interval: ${INTERVAL}" \
            --global "EnableIPv6: yes" \
            --global "Language: english" \
            --global "IconDir: /mrtg-icons" \
            --snmp-options=:::::2 \
            "${SNMP_COMMUNITY}@127.0.0.1" > "${cfg_file}.tmp" 2>/dev/null; then

            if [[ -s "${cfg_file}.tmp" ]]; then
                mv "${cfg_file}.tmp" "${cfg_file}"
                cfg_success=true
                log "SUCCESS" "Configuration generated successfully"
                break
            fi
        fi
        sleep 2
    done

    # Fallback to template if cfgmaker failed
    if [[ "${cfg_success}" != true ]]; then
        log "WARNING" "cfgmaker failed, using template configuration"
        generate_template_config "${cfg_file}"
    fi

    # Append system monitoring
    cat >> "${cfg_file}" << EOF

########################################################################
# System Health Monitoring
# Added by MRTG Professional Suite
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

# System Uptime
Target[uptime]: .1.3.6.1.2.1.1.3.0:${SNMP_COMMUNITY}@127.0.0.1:
Title[uptime]: System Uptime
PageTop[uptime]: <h1>System Uptime</h1>
MaxBytes[uptime]: 100000000
ShortLegend[uptime]: secs
YLegend[uptime]: Uptime (seconds)
Options[uptime]: growright, noinfo, nopercent

EOF

    log "SUCCESS" "MRTG configuration complete"
}

generate_template_config() {
    local cfg_file="$1"
    local interfaces=($(detect_network_interfaces))

    log "INFO" "Creating template for ${#interfaces[@]} interfaces"

    cat > "${cfg_file}" << EOF
########################################################################
# MRTG Template Configuration
# Generated: $(date)
# Interfaces detected: ${#interfaces[@]}
########################################################################

# Global settings
WorkDir: ${WEB_ROOT}/mrtg
LogDir: ${MRTG_LOG}
Interval: ${INTERVAL}
Options[_]: growright, bits
EnableIPv6: yes
Language: english
WriteExpires: Yes
WithPeak[_]: wmy

# Global HTML settings
Title[^]: MRTG Network Monitor - $(hostname)
PageTop[^]: <h1>MRTG Network Monitor - $(hostname)</h1>
XSize[_]: 600
YSize[_]: 300

EOF

    # Add each interface with speed detection
    for interface in "${interfaces[@]}"; do
        # Detect interface speed
        local speed=1000000  # Default 1Gbps in bytes
        if [[ -f "/sys/class/net/${interface}/speed" ]]; then
            local detected_speed=$(cat "/sys/class/net/${interface}/speed" 2>/dev/null | grep -o '[0-9]*' || echo "1000")
            speed=$((detected_speed * 1000000 / 8))
        elif [[ -f "/sys/class/net/${interface}/device/speed" ]]; then
            local detected_speed=$(cat "/sys/class/net/${interface}/device/speed" 2>/dev/null | grep -o '[0-9]*' || echo "1000")
            speed=$((detected_speed * 1000000 / 8))
        fi

        # Get interface description if available
        local description="${interface}"
        if command -v ethtool >/dev/null 2>&1; then
            description=$(ethtool "${interface}" 2>/dev/null | grep "Description" | cut -d: -f2- | xargs || echo "${interface}")
        fi

        cat >> "${cfg_file}" << EOF
# Interface: ${interface} - ${description}
Target[${interface}]: ${interface}:${SNMP_COMMUNITY}@127.0.0.1:
MaxBytes[${interface}]: ${speed}
Title[${interface}]: Traffic Analysis for ${interface} - ${description}
PageTop[${interface}]: <h1>Traffic Analysis for ${interface} - ${description}</h1>
YLegend[${interface}]: Bits per second
ShortLegend[${interface}]: b/s
Legend1[${interface}]: Incoming Traffic (bits/sec)
Legend2[${interface}]: Outgoing Traffic (bits/sec)
Legend3[${interface}]: Max Incoming (bits/sec)
Legend4[${interface}]: Max Outgoing (bits/sec)
WithPeak[${interface}]: wmy

EOF
    done

    log "SUCCESS" "Template configuration created"
}

setup_cron() {
    log "INFO" "Setting up cron job (interval: ${INTERVAL} minutes)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would add cron: */${INTERVAL} * * * * ${MRTG_BIN}/run-mrtg.sh"
        return 0
    fi

    # Create runner script with environment
    cat > "${MRTG_BIN}/run-mrtg.sh" << 'EOF'
#!/bin/bash
# MRTG Runner Script - Generated by MRTG Professional Suite
# This script runs MRTG and handles permissions

# Load environment
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Configuration
MRTG_CONF="/usr/local/mrtg/conf/mrtg.cfg"
MRTG_LOG="/usr/local/mrtg/logs/mrtg.log"
WEB_ROOT="'${WEB_ROOT}'"
WEB_USER="'${WEB_USER}'"
WEB_GROUP="'${WEB_GROUP}'"

# Function to log with timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${MRTG_LOG}"
}

# Run MRTG (3 passes to ensure rates are calculated)
for i in {1..3}; do
    log_message "MRTG run $i/3"
    /usr/bin/mrtg "${MRTG_CONF}" --logging "${MRTG_LOG}" 2>&1 | while read line; do
        log_message "MRTG: $line"
    done
    sleep 1
done

# Generate index
log_message "Generating index page"
/usr/bin/indexmaker "${MRTG_CONF}" --output="${WEB_ROOT}/mrtg/index.html"

# Set permissions
log_message "Setting permissions"
chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_ROOT}/mrtg" 2>/dev/null || true
chmod -R 755 "${WEB_ROOT}/mrtg" 2>/dev/null || true

log_message "Cron run completed"
EOF

    chmod +x "${MRTG_BIN}/run-mrtg.sh"

    # Remove existing MRTG cron entries
    crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab -

    # Add new cron with comment for easy identification
    (crontab -l 2>/dev/null || true; echo "# MRTG Monitoring - Added by MRTG Professional Suite v${SCRIPT_VERSION}") | crontab -
    (crontab -l 2>/dev/null; echo "*/${INTERVAL} * * * * ${MRTG_BIN}/run-mrtg.sh >/dev/null 2>&1") | crontab -

    log "SUCCESS" "Cron job installed"
}

setup_web_access() {
    log "INFO" "Configuring web access..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure web access for ${WEB_SERVER}"
        return 0
    fi

    # Create symbolic link if needed
    if [[ "${WEB_ROOT}/mrtg" != "${MRTG_HTML}" ]]; then
        ln -sfn "${WEB_ROOT}/mrtg" "${MRTG_HTML}"
    fi

    # Create .htaccess for Apache/LiteSpeed
    if [[ "${WEB_SERVER}" == "apache" ]] || [[ "${WEB_SERVER}" == "litespeed" ]] || [[ "${WEB_SERVER}" == "openlitespeed" ]]; then
        cat > "${WEB_ROOT}/mrtg/.htaccess" << EOF
# MRTG Access Control
# Generated: $(date)

# Restrict access by default
Order Deny,Allow
Deny from all
Allow from 127.0.0.1
Allow from ::1

# Allow local network (adjust as needed)
# Allow from 192.168.0.0/16
# Allow from 10.0.0.0/8

# Password protection (uncomment and configure if needed)
# AuthType Basic
# AuthName "MRTG Network Monitor"
# AuthUserFile /etc/mrtg/.htpasswd
# Require valid-user

<FilesMatch "\.(png|gif|jpg|jpeg|css|js)$">
    Order Allow,Deny
    Allow from all
</FilesMatch>
EOF
    fi

    # Create robots.txt
    cat > "${WEB_ROOT}/mrtg/robots.txt" << EOF
User-agent: *
Disallow: /
EOF

    # Create simple index if none exists
    if [[ ! -f "${WEB_ROOT}/mrtg/index.html" ]]; then
        cat > "${WEB_ROOT}/mrtg/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>MRTG Network Monitor</title>
    <meta http-equiv="refresh" content="300">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #333; color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        .content { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .info { background: #e8f4fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        h1 { margin: 0; font-size: 24px; }
        h2 { color: #333; font-size: 18px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MRTG Network Monitor</h1>
    </div>
    <div class="content">
        <div class="info">
            <h2>Monitoring Status</h2>
            <p>Initializing monitoring data... Please wait 5-10 minutes for graphs to appear.</p>
            <p>Server: $(hostname) | Date: $(date)</p>
        </div>
        <p>If graphs don't appear after 10 minutes, check:</p>
        <ul>
            <li>SNMP service is running: <code>systemctl status snmpd</code></li>
            <li>Firewall allows UDP port 161</li>
            <li>File permissions: <code>${WEB_ROOT}/mrtg</code></li>
            <li>MRTG logs: <code>${MRTG_LOG}/mrtg.log</code></li>
        </ul>
    </div>
</body>
</html>
EOF
    fi

    # Set permissions
    chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_ROOT}/mrtg" 2>/dev/null || true
    chmod -R 755 "${WEB_ROOT}/mrtg" 2>/dev/null || true

    log "SUCCESS" "Web access configured"
}

configure_panel_integration() {
    if [[ "${PANEL_TYPE}" == "none" ]] || [[ "${DRY_RUN}" == true ]]; then
        return 0
    fi

    log "INFO" "Configuring ${PANEL_TYPE} integration..."

    case "${PANEL_TYPE}" in
        "directadmin")
            local da_plugins="/usr/local/directadmin/plugins"
            local mrtg_plugin="${da_plugins}/mrtg-monitor"

            mkdir -p "${mrtg_plugin}/admin"
            mkdir -p "${mrtg_plugin}/data"
            mkdir -p "${mrtg_plugin}/hooks"

            # Plugin configuration
            cat > "${mrtg_plugin}/plugin.conf" << EOF
name=MRTG Network Monitor
version=${SCRIPT_VERSION}
desc=Enterprise-grade network traffic monitoring and bandwidth graphing
url=/plugins/mrtg-monitor/admin/
icon=graph.png
level=admin
EOF

            # Admin interface
            cat > "${mrtg_plugin}/admin/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>MRTG Network Monitor</title>
    <meta http-equiv="refresh" content="300">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f0f0f0; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
        .graph-container { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { margin: 0; font-size: 24px; }
        h2 { color: #333; margin-top: 0; }
        iframe { border: 1px solid #ddd; border-radius: 5px; background: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MRTG Network Monitor</h1>
        <p>DirectAdmin Integration | Version ${SCRIPT_VERSION}</p>
    </div>
    <div class="graph-container">
        <h2>Network Traffic Graphs</h2>
        <iframe src="/mrtg/" width="100%" height="800" frameborder="0"></iframe>
    </div>
</body>
</html>
EOF

            # Set ownership
            if id diradmin >/dev/null 2>&1; then
                chown -R diradmin:diradmin "${mrtg_plugin}"
            fi

            log "SUCCESS" "DirectAdmin plugin installed"
            ;;

        "cpanel")
            # Create symlink in cPanel's webroot
            if [[ -d "/usr/local/apache/htdocs" ]]; then
                ln -sfn "${WEB_ROOT}/mrtg" "/usr/local/apache/htdocs/mrtg"
                log "SUCCESS" "cPanel symlink created"
            fi
            ;;

        "plesk")
            # Add to Plesk default vhost
            if [[ -d "/var/www/vhosts/default/htdocs" ]]; then
                ln -sfn "${WEB_ROOT}/mrtg" "/var/www/vhosts/default/htdocs/mrtg"
                log "SUCCESS" "Plesk symlink created"
            fi
            ;;
    esac
}

initialize_mrtg() {
    log "INFO" "Initializing MRTG data collection..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would run MRTG 3 times to initialize data"
        return 0
    fi

    local mrtg_path=$(command -v mrtg || echo "/usr/bin/mrtg")
    local cfg_file="${MRTG_CONF}/mrtg.cfg"

    # Ensure directories exist
    mkdir -p "${MRTG_LOG}" "${WEB_ROOT}/mrtg"

    # 3-pass warmup
    for i in {1..3}; do
        log "INFO" "Warmup pass ${i}/3..."
        env LANG=C ${mrtg_path} "${cfg_file}" --logging "${MRTG_LOG}/mrtg.log" >/dev/null 2>&1 || true
        sleep 2
    done

    # Generate index
    local indexmaker_path=$(command -v indexmaker || echo "/usr/bin/indexmaker")
    ${indexmaker_path} "${cfg_file}" --output="${WEB_ROOT}/mrtg/index.html"

    # Set permissions
    chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_ROOT}/mrtg" 2>/dev/null || true
    chmod -R 755 "${WEB_ROOT}/mrtg" 2>/dev/null || true

    log "SUCCESS" "Initialization complete"
}

# =============================================================================
# HEALTH CHECK FUNCTIONS
# =============================================================================

verify_system_health() {
    log "INFO" "Running comprehensive system health check..."

    local errors=0
    local warnings=0

    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}              MRTG SYSTEM HEALTH DIAGNOSTIC${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

    # 1. Check MRTG Installation
    echo -e "${BOLD}1. MRTG Installation${NC}"
    if [[ -d "${MRTG_BASE}" ]]; then
        echo -e "  ${GREEN}✓${NC} MRTG base directory: ${MRTG_BASE}"
    else
        echo -e "  ${RED}✗${NC} MRTG not installed"
        ((errors++))
    fi

    if [[ -f "${MRTG_CONF}/mrtg.cfg" ]]; then
        echo -e "  ${GREEN}✓${NC} Configuration file found"
    else
        echo -e "  ${RED}✗${NC} Configuration missing"
        ((errors++))
    fi

    # 2. Check SNMP Service
    echo -e "\n${BOLD}2. SNMP Service${NC}"
    if systemctl is-active --quiet snmpd 2>/dev/null || service snmpd status 2>/dev/null | grep -q "running"; then
        echo -e "  ${GREEN}✓${NC} SNMP service is running"
    else
        echo -e "  ${RED}✗${NC} SNMP service not running"
        ((errors++))
    fi

    # Test SNMP response
    if command -v snmpget >/dev/null 2>&1; then
        if snmpget -v 2c -c "${SNMP_COMMUNITY}" -t 2 127.0.0.1 sysUpTime.0 >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} SNMP responding correctly"
        else
            echo -e "  ${RED}✗${NC} SNMP not responding - check community string"
            ((errors++))
        fi
    fi

    # 3. Check Cron
    echo -e "\n${BOLD}3. Scheduled Tasks${NC}"
    if crontab -l 2>/dev/null | grep -q "run-mrtg.sh"; then
        local cron_line=$(crontab -l 2>/dev/null | grep "run-mrtg.sh" | head -1)
        echo -e "  ${GREEN}✓${NC} Cron job found: ${cron_line}"
    else
        echo -e "  ${RED}✗${NC} No MRTG cron job found"
        ((errors++))
    fi

    # 4. Check Data Collection
    echo -e "\n${BOLD}4. Data Collection${NC}"
    if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
        local log_size=$(stat -c%s "${MRTG_LOG}/mrtg.log" 2>/dev/null || stat -f%z "${MRTG_LOG}/mrtg.log" 2>/dev/null)
        local last_mod=$(stat -c%Y "${MRTG_LOG}/mrtg.log" 2>/dev/null || stat -f%m "${MRTG_LOG}/mrtg.log" 2>/dev/null)
        local current_time=$(date +%s)
        local minutes_ago=$(( (current_time - last_mod) / 60 ))

        echo -e "  ${GREEN}✓${NC} Log file size: $(numfmt --to=iec ${log_size} 2>/dev/null || echo "${log_size} bytes")"

        if [[ ${minutes_ago} -le 10 ]]; then
            echo -e "  ${GREEN}✓${NC} Last update: ${minutes_ago} minutes ago"
        else
            echo -e "  ${YELLOW}⚠${NC} Last update: ${minutes_ago} minutes ago (may be stale)"
            ((warnings++))
        fi
    else
        echo -e "  ${RED}✗${NC} No log file found"
        ((errors++))
    fi

    # 5. Check Web Output
    echo -e "\n${BOLD}5. Web Interface${NC}"
    if [[ -d "${WEB_ROOT}/mrtg" ]]; then
        echo -e "  ${GREEN}✓${NC} Web directory exists: ${WEB_ROOT}/mrtg"

        local image_count=$(find "${WEB_ROOT}/mrtg" -name "*.png" 2>/dev/null | wc -l)
        if [[ ${image_count} -gt 0 ]]; then
            echo -e "  ${GREEN}✓${NC} Found ${image_count} graph images"
        else
            echo -e "  ${YELLOW}⚠${NC} No graph images found (waiting for first run)"
            ((warnings++))
        fi

        if [[ -f "${WEB_ROOT}/mrtg/index.html" ]]; then
            echo -e "  ${GREEN}✓${NC} Index page exists"
        else
            echo -e "  ${YELLOW}⚠${NC} Index page missing"
            ((warnings++))
        fi

        # Check permissions
        if [[ -w "${WEB_ROOT}/mrtg" ]]; then
            echo -e "  ${GREEN}✓${NC} Directory is writable"
        else
            echo -e "  ${RED}✗${NC} Directory not writable"
            ((errors++))
        fi
    else
        echo -e "  ${RED}✗${NC} Web directory missing"
        ((errors++))
    fi

    # 6. Check Network Interfaces
    echo -e "\n${BOLD}6. Network Interfaces${NC}"
    local interfaces=($(detect_network_interfaces))
    echo -e "  ${GREEN}✓${NC} Detected ${#interfaces[@]} active interfaces"
    for interface in "${interfaces[@]}"; do
        if [[ -f "${WEB_ROOT}/mrtg/${interface}.html" ]]; then
            echo -e "  ${GREEN}  ✓ ${interface}: monitoring active"
        else
            echo -e "  ${YELLOW}  ○ ${interface}: waiting for data"
        fi
    done

    # 7. Firewall Status
    echo -e "\n${BOLD}7. Firewall Configuration${NC}"
    if command -v csf >/dev/null 2>&1 && [[ -f /etc/csf/csf.conf ]]; then
        if grep -q "161" /etc/csf/csf.conf; then
            echo -e "  ${GREEN}✓${NC} CSF allows SNMP (port 161)"
        else
            echo -e "  ${YELLOW}⚠${NC} CSF may block SNMP - port 161 not found"
            ((warnings++))
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --list-services 2>/dev/null | grep -q "snmp"; then
            echo -e "  ${GREEN}✓${NC} Firewalld allows SNMP"
        else
            echo -e "  ${YELLOW}⚠${NC} SNMP service not enabled in firewalld"
            ((warnings++))
        fi
    elif command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "161"; then
            echo -e "  ${GREEN}✓${NC} UFW allows SNMP"
        else
            echo -e "  ${YELLOW}⚠${NC} UFW may block SNMP"
            ((warnings++))
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} No firewall detected or unknown type"
    fi

    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}DIAGNOSTIC SUMMARY${NC}"
    echo -e "  Errors: ${errors}   Warnings: ${warnings}"

    if [[ ${errors} -eq 0 && ${warnings} -eq 0 ]]; then
        echo -e "\n${GREEN}${BOLD}✓ SYSTEM HEALTH: PERFECT${NC}"
        echo -e "${GREEN}All systems operational${NC}"
    elif [[ ${errors} -eq 0 && ${warnings} -gt 0 ]]; then
        echo -e "\n${YELLOW}${BOLD}⚠ SYSTEM HEALTH: GOOD WITH WARNINGS${NC}"
        echo -e "${YELLOW}Address warnings for optimal performance${NC}"
    else
        echo -e "\n${RED}${BOLD}✗ SYSTEM HEALTH: ISSUES DETECTED${NC}"
        echo -e "${RED}Please fix the ${errors} error(s) above${NC}"
    fi

    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

    # Return error count for scripting
    return ${errors}
}

repair_installation() {
    log "INFO" "Attempting to repair MRTG installation..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would attempt repair"
        return 0
    fi

    # Backup first
    backup_config

    # Restart SNMP with proper configuration
    log "INFO" "Restarting SNMP service..."
    if systemctl list-units --full -all 2>/dev/null | grep -q 'snmpd.service'; then
        systemctl unmask snmpd >/dev/null 2>&1 || true
        systemctl enable snmpd >/dev/null 2>&1 || true
        systemctl restart snmpd
    else
        service snmpd restart
    fi
    sleep 3

    # Verify SNMP community
    if [[ -z "${SNMP_COMMUNITY}" ]]; then
        if [[ -f "${MRTG_CONF}/install.conf" ]]; then
            source "${MRTG_CONF}/install.conf"
        fi
    fi

    # Regenerate config
    log "INFO" "Regenerating MRTG configuration..."
    generate_mrtg_config

    # Reinitialize
    initialize_mrtg

    # Check cron
    if ! crontab -l 2>/dev/null | grep -q "run-mrtg.sh"; then
        log "INFO" "Reinstalling cron job..."
        setup_cron
    fi

    # Fix permissions
    log "INFO" "Fixing permissions..."
    chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_ROOT}/mrtg" 2>/dev/null || true
    chmod -R 755 "${WEB_ROOT}/mrtg" 2>/dev/null || true

    log "SUCCESS" "Repair attempt completed"

    # Run health check
    verify_system_health
}

# =============================================================================
# BACKUP AND RESTORE FUNCTIONS
# =============================================================================

backup_config() {
    local backup_file="${BACKUP_DIR}/mrtg-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

    log "INFO" "Creating backup: ${backup_file}"

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would backup to: ${backup_file}"
        return 0
    fi

    mkdir -p "${BACKUP_DIR}"

    # Create backup of all important files
    tar -czf "${backup_file}" \
        --exclude="${MRTG_LOG}/*" \
        --exclude="${MRTG_VAR}/*" \
        "${MRTG_CONF}" \
        "${MRTG_BIN}" \
        /etc/snmp/snmpd.conf \
        2>/dev/null || true

    # Save installation info
    cat > "${BACKUP_DIR}/install-info.txt" << EOF
MRTG Installation Backup
Date: $(date)
Version: ${SCRIPT_VERSION}
Web Server: ${WEB_SERVER}
Web User: ${WEB_USER}
Web Root: ${WEB_ROOT}
SNMP Community: ${SNMP_COMMUNITY}
Panel: ${PANEL_TYPE}
EOF

    log "SUCCESS" "Backup created: ${backup_file}"
    echo -e "${GREEN}Backup saved to: ${backup_file}${NC}"
}

restore_config() {
    log "INFO" "Available backups:"

    local backups=($(ls -1 "${BACKUP_DIR}"/*.tar.gz 2>/dev/null))

    if [[ ${#backups[@]} -eq 0 ]]; then
        log "ERROR" "No backups found in ${BACKUP_DIR}"
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

    if confirm_action "Restore from $(basename "${selected}")? This will overwrite current configuration."; then
        log "INFO" "Restoring from: ${selected}"

        # Backup current config first
        backup_config

        # Stop cron temporarily
        crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | crontab -

        # Restore files
        tar -xzf "${selected}" -C /

        # Restart services
        systemctl restart snmpd 2>/dev/null || service snmpd restart 2>/dev/null || true

        # Re-add cron
        setup_cron

        log "SUCCESS" "Restore completed"
    fi
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

    if [[ "${FORCE_MODE}" != true ]]; then
        echo -e "${RED}${BOLD}WARNING: This will remove MRTG and all configurations${NC}"
        echo -e "The following will be affected:"
        echo -e "  - ${MRTG_BASE} (MRTG installation)"
        echo -e "  - ${WEB_ROOT}/mrtg (Web files)"
        echo -e "  - /etc/snmp/snmpd.conf (SNMP config)"
        echo -e "  - MRTG cron jobs"
        echo -e "  - DirectAdmin plugin (if installed)"
        echo ""

        if ! confirm_action "Are you sure you want to continue?"; then
            log "INFO" "Uninstall cancelled"
            return 0
        fi
    fi

    # Create backup before uninstall
    backup_config

    # Remove cron jobs
    log "INFO" "Removing cron jobs..."
    crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab -

    # Remove DirectAdmin plugin
    if [[ -d "/usr/local/directadmin/plugins/mrtg-monitor" ]]; then
        log "INFO" "Removing DirectAdmin plugin..."
        rm -rf "/usr/local/directadmin/plugins/mrtg-monitor"
    fi

    # Ask about packages
    if confirm_action "Remove MRTG and SNMP packages?"; then
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

    # Ask about data
    if confirm_action "Remove all MRTG data and configurations?"; then
        log "INFO" "Removing MRTG files..."
        rm -rf "${MRTG_BASE}"
        rm -rf "${MRTG_VAR}"
        rm -rf "${WEB_ROOT}/mrtg"

        # Restore original SNMP config if exists
        local snmp_backup=$(ls -1 /etc/snmp/snmpd.conf.backup.* 2>/dev/null | head -1)
        if [[ -n "${snmp_backup}" ]] && confirm_action "Restore original SNMP configuration?"; then
            cp "${snmp_backup}" /etc/snmp/snmpd.conf
            systemctl restart snmpd 2>/dev/null || service snmpd restart 2>/dev/null || true
        fi
    fi

    log "SUCCESS" "Uninstall completed"
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
                    PROFESSIONAL MONITORING SUITE
================================================================================
Version: ${SCRIPT_VERSION} | Author: ${SCRIPT_AUTHOR}
GitHub: ${SCRIPT_URL}
================================================================================

This installer will:
  ✓ Detect your existing web server (Apache/Nginx/LiteSpeed)
  ✓ Configure SNMP with secure community string
  ✓ Set up MRTG for network monitoring
  ✓ Integrate with your control panel (if detected)
  ✓ NEVER install or modify your web server

EOF

    # Check root
    check_root

    # Acquire lock
    acquire_lock

    # Detect system
    detect_os
    detect_control_panel
    detect_web_server

    # Show detected configuration
    echo -e "\n${BOLD}Detected Configuration:${NC}"
    echo -e "  OS: ${GREEN}${OS_NAME} ${OS_VERSION}${NC}"
    echo -e "  Web Server: ${GREEN}${WEB_SERVER}${NC}"
    echo -e "  Web User: ${GREEN}${WEB_USER}${NC}"
    echo -e "  Web Root: ${GREEN}${WEB_ROOT}${NC}"

    if [[ "${PANEL_TYPE}" != "none" ]]; then
        echo -e "  Control Panel: ${GREEN}${PANEL_TYPE}${NC}"
    fi

    # Get user input
    echo -e "\n${BOLD}Configuration Options:${NC}"
    read -p "Monitoring interval in minutes [${DEFAULT_INTERVAL}]: " interval
    INTERVAL=${interval:-${DEFAULT_INTERVAL}}

    read -p "SNMP Community String [auto-generate]: " snmp_input
    SNMP_COMMUNITY=${snmp_input}

    read -p "Notification email [${DEFAULT_EMAIL}]: " email_input
    DEFAULT_EMAIL=${email_input:-${DEFAULT_EMAIL}}

    # Show summary
    echo -e "\n${YELLOW}Installation Summary:${NC}"
    echo -e "  Interval: ${INTERVAL} minutes"
    echo -e "  SNMP: ${SNMP_COMMUNITY:-"<auto-generated>"}"
    echo -e "  Email: ${DEFAULT_EMAIL}"
    echo -e "  Web Directory: ${WEB_ROOT}/mrtg"
    echo ""

    if ! confirm_action "Proceed with installation?"; then
        log "INFO" "Installation cancelled"
        return 0
    fi

    # Run installation steps
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

    # Save installation config
    cat > "${MRTG_CONF}/install.conf" << EOF
# MRTG Installation Configuration
# Generated: $(date)

WEB_ROOT="${WEB_ROOT}"
WEB_USER="${WEB_USER}"
WEB_GROUP="${WEB_GROUP}"
WEB_SERVER="${WEB_SERVER}"
SNMP_COMMUNITY="${SNMP_COMMUNITY}"
PANEL_TYPE="${PANEL_TYPE}"
INTERVAL="${INTERVAL}"
INSTALL_DATE="$(date)"
SCRIPT_VERSION="${SCRIPT_VERSION}"
EOF

    log "SUCCESS" "Installation completed!"

    # Show access information
    local server_ip=$(detect_ip_address)
    echo -e "\n${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}                    INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

    echo -e "Access MRTG: ${BLUE}http://${server_ip}/mrtg/${NC}"
    echo -e "SNMP Community: ${YELLOW}${SNMP_COMMUNITY}${NC} ${RED}(keep this secure!)${NC}"
    echo -e "Configuration: ${CYAN}${MRTG_CONF}/mrtg.cfg${NC}"
    echo -e "Logs: ${CYAN}${MRTG_LOG}/mrtg.log${NC}"
    echo -e "Cron: ${CYAN}*/${INTERVAL} * * * *${NC}\n"

    echo -e "To check status: ${CYAN}${SCRIPT_NAME} --status${NC}"
    echo -e "To uninstall: ${CYAN}${SCRIPT_NAME} --uninstall${NC}\n"

    # Run health check
    verify_system_health
}

# =============================================================================
# INTERACTIVE MENU
# =============================================================================

show_menu() {
    clear
    cat << "EOF"
================================================================================
                    MRTG PROFESSIONAL MONITORING SUITE
================================================================================
Version: ${SCRIPT_VERSION} | Enterprise Edition
================================================================================

EOF

    echo -e "${BOLD}MAIN MENU${NC}\n"

    echo -e "  ${GREEN}1)${NC} Install MRTG (Full installation wizard)"
    echo -e "  ${GREEN}2)${NC} Uninstall MRTG"
    echo -e "  ${GREEN}3)${NC} Run Health Check"
    echo -e "  ${GREEN}4)${NC} Repair Installation"
    echo -e "  ${GREEN}5)${NC} Backup Configuration"
    echo -e "  ${GREEN}6)${NC} Restore from Backup"
    echo -e "  ${GREEN}7)${NC} Add/Update Cron Job"
    echo -e "  ${GREEN}8)${NC} Remove Cron Job"
    echo -e "  ${GREEN}9)${NC} View Logs"
    echo -e "  ${GREEN}10)${NC} Regenerate Index Page"
    echo -e "  ${GREEN}11)${NC} Test Configuration"
    echo -e "  ${GREEN}12)${NC} Dry Run (Test Mode)"
    echo -e "  ${GREEN}0)${NC} Exit\n"

    read -p "Enter your choice [0-12]: " choice

    case ${choice} in
        1) installation_wizard ;;
        2) uninstall_mrtg ;;
        3)
            detect_web_server
            verify_system_health
            ;;
        4)
            detect_web_server
            repair_installation
            ;;
        5) backup_config ;;
        6) restore_config ;;
        7)
            detect_web_server
            read -p "Interval in minutes [${DEFAULT_INTERVAL}]: " interval
            INTERVAL=${interval:-${DEFAULT_INTERVAL}}
            setup_cron
            ;;
        8)
            if confirm_action "Remove MRTG cron job?"; then
                crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab -
                log "SUCCESS" "Cron job removed"
            fi
            ;;
        9)
            if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
                tail -50 "${MRTG_LOG}/mrtg.log"
            else
                log "ERROR" "Log file not found"
            fi
            ;;
        10)
            if [[ -f "${MRTG_CONF}/mrtg.cfg" ]]; then
                detect_web_server
                indexmaker "${MRTG_CONF}/mrtg.cfg" --output="${WEB_ROOT}/mrtg/index.html"
                chown "${WEB_USER}:${WEB_GROUP}" "${WEB_ROOT}/mrtg/index.html" 2>/dev/null || true
                log "SUCCESS" "Index page regenerated"
            else
                log "ERROR" "Configuration not found"
            fi
            ;;
        11)
            if [[ -f "${MRTG_CONF}/mrtg.cfg" ]]; then
                env LANG=C mrtg "${MRTG_CONF}/mrtg.cfg" --check
            else
                log "ERROR" "Configuration not found"
            fi
            ;;
        12)
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
# COMMAND LINE INTERFACE
# =============================================================================

print_help() {
    cat << EOF
${BOLD}NAME${NC}
    ${SCRIPT_NAME} - MRTG Professional Monitoring Suite v${SCRIPT_VERSION}

${BOLD}SYNOPSIS${NC}
    ${SCRIPT_NAME} [OPTIONS]

${BOLD}DESCRIPTION${NC}
    Enterprise-grade MRTG installer for hosting environments. Detects and works
    with existing web servers and control panels without modifying them.

${BOLD}OPTIONS${NC}
    --install, -i     Run installation wizard
    --uninstall, -u   Complete removal with backup
    --status, -s      Full system health check
    --repair, -r      Attempt to repair broken installation
    --backup, -b      Backup current configuration
    --restore, -R     Restore from backup
    --dry-run         Test without making changes
    --force           Skip confirmations (use with caution)
    --version, -v     Show version information
    --help, -h        Show this help message

${BOLD}EXAMPLES${NC}
    ${SCRIPT_NAME} --install           # Interactive installation
    ${SCRIPT_NAME} --status            # Check system health
    ${SCRIPT_NAME} --repair            # Fix common issues
    ${SCRIPT_NAME} --uninstall         # Remove MRTG completely
    ${SCRIPT_NAME} --dry-run            # Test without changes

${BOLD}FILES${NC}
    ${MRTG_BASE}              Main installation directory
    ${MRTG_CONF}              Configuration files
    ${MRTG_LOG}               Log files
    ${BACKUP_DIR}             Backup directory

${BOLD}AUTHOR${NC}
    Written by ${SCRIPT_AUTHOR}
    GitHub: ${SCRIPT_URL}

${BOLD}REPORTING BUGS${NC}
    ${SCRIPT_URL}/issues

EOF
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Create log file
    touch "${LOG_FILE}"
    chmod 644 "${LOG_FILE}"

    # Parse command line arguments
    if [[ $# -gt 0 ]]; then
        case $1 in
            --install|-i)
                check_root
                installation_wizard
                ;;
            --uninstall|-u)
                check_root
                shift
                [[ "$1" == "--force" ]] && FORCE_MODE=true
                uninstall_mrtg
                ;;
            --status|-s)
                check_root
                detect_web_server
                verify_system_health
                ;;
            --repair|-r)
                check_root
                detect_web_server
                repair_installation
                ;;
            --backup|-b)
                check_root
                detect_web_server
                backup_config
                ;;
            --restore|-R)
                check_root
                restore_config
                ;;
            --dry-run)
                check_root
                DRY_RUN=true
                installation_wizard
                ;;
            --force)
                FORCE_MODE=true
                shift
                main "$@"
                ;;
            --version|-v)
                echo "MRTG Professional Suite ${SCRIPT_VERSION}"
                ;;
            --help|-h)
                print_help
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

# Trap errors and cleanup
trap cleanup EXIT
trap 'error_exit "Interrupted on line $LINENO"' INT TERM

# Run main function
main "$@"
