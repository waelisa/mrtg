#!/bin/bash
#
# MRTG Professional Monitoring Suite - Enterprise Edition v1.6.0
# Production-Hardened Network Monitoring for Hosting Environments
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
# Version:     v1.6.0
# Build Date:  02/27/2026
# License:     MIT
#
# DESCRIPTION:
#   Zero-assumption MRTG installer for production hosting environments
#   - Detects and works with ANY existing web server (Apache/Nginx/LiteSpeed)
#   - Full DirectAdmin/cPanel/Plesk integration
#   - Smart CSF/firewalld/UFW configuration with syntax safety
#   - 3-pass warmup to eliminate first-run errors
#   - SNMP stabilization delay for slow servers
#   - Complete uninstall with rollback
#   - Real-time health monitoring
#   - Automatic updates from GitHub
#
# USAGE:
#   ./install-mrtg.sh [OPTIONS]
#
# OPTIONS:
#   --install, -i     Full installation wizard
#   --uninstall, -u   Complete removal with backup
#   --status, -s      Detailed health check
#   --repair, -r      Auto-fix common issues
#   --backup, -b      Backup configuration
#   --restore, -R     Restore from backup
#   --update, -U      Self-update from GitHub
#   --dry-run         Test without changes
#   --force           Skip confirmations
#   --help, -h        Show this help
#
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# GLOBAL CONSTANTS
# =============================================================================

readonly SCRIPT_VERSION="v1.6.0"
readonly SCRIPT_AUTHOR="Wael Isa"
readonly REPO_URL="https://raw.githubusercontent.com/waelisa/mrtg/main/install-mrtg.sh"
readonly LOG_FILE="/var/log/mrtg-installer.log"
readonly BACKUP_DIR="/root/mrtg-backups"
readonly LOCK_FILE="/var/run/mrtg-installer.lock"
readonly SCRIPT_NAME=$(basename "$0")

# Installation paths
readonly MRTG_BASE="/usr/local/mrtg"
readonly MRTG_CONF="${MRTG_BASE}/conf"
readonly MRTG_LOG="${MRTG_BASE}/logs"
readonly MRTG_HTML="${MRTG_BASE}/html"
readonly MRTG_BIN="${MRTG_BASE}/bin"
readonly MRTG_VAR="/var/lib/mrtg"

# Default values
DEFAULT_INTERVAL=5
DEFAULT_EMAIL="root@localhost"
SNMP_COMMUNITY=""
WEB_ROOT=""
WEB_USER=""
WEB_GROUP=""
WEB_SERVER="unknown"
PANEL_TYPE="none"
INTERVAL=${DEFAULT_INTERVAL}
FORCE_MODE=false
DRY_RUN=false

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

# =============================================================================
# SELF-UPDATE FUNCTION
# =============================================================================

self_update() {
    log "INFO" "Checking for updates from GitHub..."

    local tmp_file="/tmp/mrtg_update_$$.sh"
    local backup_file="/tmp/mrtg_backup_$$.sh"

    # Download latest version
    if command -v curl >/dev/null 2>&1; then
        if ! curl -s -o "${tmp_file}" "${REPO_URL}"; then
            log "ERROR" "Failed to download update"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -q -O "${tmp_file}" "${REPO_URL}"; then
            log "ERROR" "Failed to download update"
            return 1
        fi
    else
        log "ERROR" "Neither curl nor wget found"
        return 1
    fi

    # Check if download was successful
    if [[ ! -s "${tmp_file}" ]]; then
        log "ERROR" "Downloaded file is empty"
        rm -f "${tmp_file}"
        return 1
    fi

    # Get versions
    local current_ver=$(grep "^readonly SCRIPT_VERSION=" "$0" | cut -d'"' -f2)
    local new_ver=$(grep "^readonly SCRIPT_VERSION=" "${tmp_file}" | cut -d'"' -f2)

    if [[ -z "${new_ver}" ]]; then
        log "ERROR" "Invalid update file"
        rm -f "${tmp_file}"
        return 1
    fi

    if [[ "${current_ver}" == "${new_ver}" ]]; then
        log "SUCCESS" "Script is already up to date (${current_ver})"
        rm -f "${tmp_file}"
        return 0
    fi

    log "INFO" "Current version: ${current_ver}, New version: ${new_ver}"

    # Backup current script
    cp "$0" "${backup_file}"
    chmod 644 "${backup_file}"

    # Apply update
    if cp "${tmp_file}" "$0"; then
        chmod +x "$0"
        log "SUCCESS" "Updated to version ${new_ver}"
        log "INFO" "Backup saved to: ${backup_file}"
        rm -f "${tmp_file}"

        echo -e "\n${GREEN}Please restart the script to use the new version.${NC}"
        exit 0
    else
        log "ERROR" "Failed to apply update"
        cp "${backup_file}" "$0"
        rm -f "${tmp_file}" "${backup_file}"
        return 1
    fi
}

# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

detect_os() {
    log "INFO" "Detecting operating system..."

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="${NAME}"
        OS_VERSION="${VERSION_ID}"
        OS_ID="${ID}"
        OS_ID_LIKE="${ID_LIKE:-}"
        log "SUCCESS" "Detected: ${OS_NAME} ${OS_VERSION}"
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
        OS_ID="unknown"
        log "WARNING" "Could not detect OS"
    fi
}

detect_control_panel() {
    PANEL_TYPE="none"
    PANEL_VERSION="unknown"

    # DirectAdmin
    if [[ -d /usr/local/directadmin ]]; then
        PANEL_TYPE="directadmin"
        if [[ -f /usr/local/directadmin/conf/directadmin.conf ]]; then
            PANEL_VERSION=$(grep -i "^version=" /usr/local/directadmin/conf/directadmin.conf 2>/dev/null | cut -d= -f2 || echo "unknown")
        fi
        log "SUCCESS" "DirectAdmin detected (v${PANEL_VERSION})"

    # cPanel
    elif [[ -d /usr/local/cpanel ]]; then
        PANEL_TYPE="cpanel"
        if command -v /usr/local/cpanel/cpanel >/dev/null; then
            PANEL_VERSION=$(/usr/local/cpanel/cpanel -V 2>/dev/null | head -1 | tr -d ' ' || echo "unknown")
        fi
        log "SUCCESS" "cPanel detected (v${PANEL_VERSION})"

    # Plesk
    elif [[ -d /usr/local/psa ]]; then
        PANEL_TYPE="plesk"
        if command -v plesk >/dev/null; then
            PANEL_VERSION=$(plesk version 2>/dev/null | grep -i "version" | head -1 | awk '{print $2}' || echo "unknown")
        fi
        log "SUCCESS" "Plesk detected (v${PANEL_VERSION})"

    # ISPConfig
    elif [[ -d /usr/local/ispconfig ]]; then
        PANEL_TYPE="ispconfig"
        log "SUCCESS" "ISPConfig detected"

    # VestaCP
    elif [[ -d /usr/local/vesta ]]; then
        PANEL_TYPE="vestacp"
        log "SUCCESS" "VestaCP detected"

    # Webmin/Virtualmin
    elif [[ -d /usr/share/webmin ]] || [[ -d /usr/libexec/webmin ]]; then
        PANEL_TYPE="webmin"
        log "SUCCESS" "Webmin detected"
    fi
}

detect_web_server() {
    log "INFO" "Detecting active web server..."

    local web_servers_found=()

    # Check for running processes
    if pgrep -x "nginx" >/dev/null 2>&1; then
        WEB_SERVER="nginx"
        WEB_USER=$(ps aux | grep nginx | grep -v grep | head -1 | awk '{print $1}')
        WEB_GROUP=$(id -gn "${WEB_USER}" 2>/dev/null || echo "${WEB_USER}")
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

    if pgrep -x "openlitespeed" >/dev/null 2>&1; then
        WEB_SERVER="openlitespeed"
        WEB_USER="nobody"
        WEB_GROUP="nobody"
        web_servers_found+=("openlitespeed (active)")
    fi

    if pgrep -x "caddy" >/dev/null 2>&1; then
        WEB_SERVER="caddy"
        WEB_USER=$(ps aux | grep caddy | grep -v grep | head -1 | awk '{print $1}')
        WEB_GROUP=$(id -gn "${WEB_USER}" 2>/dev/null || echo "${WEB_USER}")
        web_servers_found+=("caddy (active)")
    fi

    # Panel-specific overrides
    if [[ "${PANEL_TYPE}" == "directadmin" ]]; then
        WEB_USER="diradmin"
        WEB_GROUP="diradmin"
        if [[ -z "${WEB_SERVER}" ]] || [[ "${WEB_SERVER}" == "unknown" ]]; then
            WEB_SERVER="apache"
        fi
    elif [[ "${PANEL_TYPE}" == "cpanel" ]]; then
        WEB_USER="apache"
        WEB_GROUP="apache"
        WEB_SERVER="apache"
    elif [[ "${PANEL_TYPE}" == "plesk" ]]; then
        WEB_USER="www-data"
        WEB_GROUP="www-data"
        WEB_SERVER="apache"
    fi

    # If multiple servers found, prioritize
    if [[ ${#web_servers_found[@]} -gt 1 ]]; then
        log "WARNING" "Multiple web servers detected: ${web_servers_found[*]}"
        # Priority: nginx > apache > litespeed
        for server in nginx apache litespeed openlitespeed caddy; do
            if [[ " ${web_servers_found[*]} " =~ ${server} ]]; then
                WEB_SERVER="${server}"
                log "INFO" "Prioritizing: ${WEB_SERVER}"
                break
            fi
        done
    fi

    # No web server found
    if [[ "${WEB_SERVER}" == "unknown" ]] || [[ -z "${WEB_SERVER}" ]]; then
        log "ERROR" "No supported web server detected"
        log "INFO" "Please ensure Apache, Nginx, or LiteSpeed is installed and running"
        exit 1
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
                WEB_ROOT="/var/www/html"
            else
                WEB_ROOT="/var/www/html"
            fi
            ;;
        "cpanel")
            if [[ -d "/usr/local/apache/htdocs" ]]; then
                WEB_ROOT="/usr/local/apache/htdocs"
            elif [[ -d "/var/www/html" ]]; then
                WEB_ROOT="/var/www/html"
            else
                WEB_ROOT="/usr/local/apache/htdocs"
            fi
            ;;
        "plesk")
            if [[ -d "/var/www/vhosts/default/htdocs" ]]; then
                WEB_ROOT="/var/www/vhosts/default/htdocs"
            elif [[ -d "/var/www/vhosts" ]]; then
                WEB_ROOT="/var/www/vhosts"
            else
                WEB_ROOT="/var/www/html"
            fi
            ;;
        *)
            # Server-specific roots
            case "${WEB_SERVER}" in
                "nginx")
                    if [[ -d "/usr/share/nginx/html" ]]; then
                        WEB_ROOT="/usr/share/nginx/html"
                    elif [[ -d "/var/www/html" ]]; then
                        WEB_ROOT="/var/www/html"
                    elif [[ -d "/srv/www/htdocs" ]]; then
                        WEB_ROOT="/srv/www/htdocs"
                    else
                        WEB_ROOT="/var/www/html"
                    fi
                    ;;
                "apache")
                    if [[ -d "/var/www/html" ]]; then
                        WEB_ROOT="/var/www/html"
                    elif [[ -d "/var/www" ]]; then
                        WEB_ROOT="/var/www"
                    elif [[ -d "/srv/www/htdocs" ]]; then
                        WEB_ROOT="/srv/www/htdocs"
                    else
                        WEB_ROOT="/var/www/html"
                    fi
                    ;;
                "litespeed"|"openlitespeed")
                    if [[ -d "/usr/local/lsws/htdocs" ]]; then
                        WEB_ROOT="/usr/local/lsws/htdocs"
                    else
                        WEB_ROOT="/var/www/html"
                    fi
                    ;;
                "caddy")
                    if [[ -d "/var/www/html" ]]; then
                        WEB_ROOT="/var/www/html"
                    else
                        WEB_ROOT="/var/www/html"
                    fi
                    ;;
                *)
                    WEB_ROOT="/var/www/html"
                    ;;
            esac
            ;;
    esac

    # Create web root if it doesn't exist
    if [[ ! -d "${WEB_ROOT}" ]]; then
        log "WARNING" "Creating web root: ${WEB_ROOT}"
        mkdir -p "${WEB_ROOT}"
    fi

    # Create mrtg subdirectory
    WEB_MRTG_DIR="${WEB_ROOT}/mrtg"
    mkdir -p "${WEB_MRTG_DIR}"

    log "INFO" "Web directory: ${WEB_MRTG_DIR}"
}

detect_network_interfaces() {
    local interfaces=()

    # Get all active network interfaces
    while IFS= read -r interface; do
        # Skip virtual interfaces
        if [[ ! "${interface}" =~ ^(lo|virbr|docker|veth|br-|tun|vnet) ]] && \
           ip link show "${interface}" 2>/dev/null | grep -q "UP"; then
            interfaces+=("${interface}")
        fi
    done < <(ls /sys/class/net/ 2>/dev/null || ip link show | awk -F': ' '/^[0-9]+: / {print $2}' | cut -d@ -f1)

    # Fallback
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
        ip=$(ip route get 1 2>/dev/null | awk '{print $NF;exit}')
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
# PRODUCTION-HARDENED INSTALLATION FUNCTIONS
# =============================================================================

install_dependencies() {
    log "INFO" "Installing MRTG and SNMP packages..."

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
            log "WARNING" "Unknown OS, attempting generic installation"
            if command -v yum >/dev/null; then
                yum install -y mrtg net-snmp net-snmp-utils
            elif command -v apt-get >/dev/null; then
                apt-get update && apt-get install -y mrtg snmpd snmp
            else
                error_exit "Cannot install packages - unsupported package manager"
            fi
            ;;
    esac

    # Verify installations
    local missing=()
    for cmd in mrtg snmpd cfgmaker indexmaker; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing+=("${cmd}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log "WARNING" "Missing commands: ${missing[*]}"
    else
        log "SUCCESS" "All dependencies installed"
    fi
}

configure_snmp() {
    log "INFO" "Configuring SNMP..."

    # Generate secure community if not set
    if [[ -z "${SNMP_COMMUNITY}" ]]; then
        if command -v openssl >/dev/null 2>&1; then
            SNMP_COMMUNITY="mrtg_$(openssl rand -hex 8)"
        else
            SNMP_COMMUNITY="mrtg_$(date +%s | sha256sum | base64 | head -c 16 | tr -d '=')"
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
proc  mysql 10 5
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

# Access control
access  MyROGroup   ""         any       noauth    exact   all    none   none

# Disable default community
com2sec paranoid default public
group paranoid v1 paranoid
group paranoid v2c paranoid
access paranoid "" any noauth exact system none none

EOF

    chmod 600 /etc/snmp/snmpd.conf

    # Start SNMP service
    if systemctl list-units --full -all 2>/dev/null | grep -q 'snmpd.service'; then
        systemctl unmask snmpd >/dev/null 2>&1 || true
        systemctl enable snmpd >/dev/null 2>&1 || true
        systemctl restart snmpd
    else
        service snmpd restart
    fi

    # CRITICAL: Wait for SNMP to fully initialize
    # Some servers (especially cloud VPS) need extra time for the service to bind
    log "INFO" "Waiting for SNMP to stabilize (3 seconds)..."
    sleep 3

    # Verify SNMP is working
    local max_attempts=5
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if command -v snmpwalk >/dev/null 2>&1; then
            if snmpwalk -v 2c -c "${SNMP_COMMUNITY}" -t 2 127.0.0.1 system 2>/dev/null | grep -q "sysName"; then
                log "SUCCESS" "SNMP verified"
                break
            fi
        fi
        log "INFO" "Waiting for SNMP response (attempt ${attempt}/${max_attempts})..."
        sleep 2
        ((attempt++))
    done

    if [[ $attempt -gt $max_attempts ]]; then
        log "WARNING" "SNMP verification failed - check configuration"
    fi
}

configure_firewall() {
    log "INFO" "Configuring firewall for SNMP (UDP 161)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure firewall for SNMP"
        return 0
    fi

    local firewall_configured=false

    # =====================================================================
    # CSF (ConfigServer Firewall) - Common in DirectAdmin/cPanel
    # SAFE HANDLING: Avoid double commas and syntax errors
    # =====================================================================
    if [[ -f /etc/csf/csf.conf ]]; then
        log "INFO" "CSF firewall detected - applying safe configuration"

        # Backup CSF config
        cp /etc/csf/csf.conf "/etc/csf/csf.conf.backup.$(date +%Y%m%d-%H%M%S)"

        local csf_modified=false

        # Process UDP_IN and UDP_OUT safely
        for port_type in "UDP_IN" "UDP_OUT"; do
            # Check if port 161 is already present
            if ! grep -q "161" /etc/csf/csf.conf; then
                # Get current value
                local current=$(grep "^${port_type} =" /etc/csf/csf.conf | cut -d'"' -f2)

                # Case 1: Empty string - just set to "161"
                if [[ -z "${current}" ]]; then
                    sed -i "s/^${port_type} = \"\"/${port_type} = \"161\"/" /etc/csf/csf.conf
                    log "INFO" "Set ${port_type} to \"161\""
                    csf_modified=true

                # Case 2: Non-empty string - add to beginning with comma
                else
                    # Add to beginning to avoid trailing comma issues
                    sed -i "s/^${port_type} = \"${current}\"/${port_type} = \"161,${current}\"/" /etc/csf/csf.conf
                    log "INFO" "Added 161 to ${port_type}"
                    csf_modified=true
                fi
            fi
        done

        # Only restart CSF if changes were made
        if [[ "${csf_modified}" == true ]]; then
            csf -r >/dev/null 2>&1
            log "SUCCESS" "CSF restarted with new rules"
        else
            log "INFO" "CSF already allows SNMP"
        fi

        firewall_configured=true
    fi

    # =====================================================================
    # Firewalld (RHEL/CentOS/Alma/Rocky)
    # =====================================================================
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log "INFO" "Firewalld detected"
        if ! firewall-cmd --list-services --permanent | grep -q "snmp"; then
            firewall-cmd --permanent --add-service=snmp
            firewall-cmd --reload >/dev/null
            log "SUCCESS" "Firewalld configured"
        else
            log "INFO" "SNMP already allowed in firewalld"
        fi
        firewall_configured=true
    fi

    # =====================================================================
    # UFW (Ubuntu/Debian)
    # =====================================================================
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
        log "INFO" "UFW detected"
        if ! ufw status | grep -q "161"; then
            ufw allow snmp >/dev/null 2>&1
            log "SUCCESS" "UFW configured"
        else
            log "INFO" "SNMP already allowed in UFW"
        fi
        firewall_configured=true
    fi

    # =====================================================================
    # iptables (fallback)
    # =====================================================================
    if [[ "${firewall_configured}" == false ]] && command -v iptables >/dev/null 2>&1; then
        log "INFO" "Configuring iptables"

        if ! iptables -C INPUT -p udp --dport 161 -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p udp --dport 161 -s 127.0.0.1 -j ACCEPT
            iptables -A INPUT -p udp --dport 161 -m state --state NEW -j ACCEPT
            log "SUCCESS" "iptables rules added"

            # Save rules
            if [[ -f /etc/redhat-release ]]; then
                service iptables save >/dev/null 2>&1 || true
            elif [[ -f /etc/debian_version ]]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            fi
        fi
        firewall_configured=true
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
        "${WEB_MRTG_DIR}"
    )

    for dir in "${dirs[@]}"; do
        if [[ ! -d "${dir}" ]]; then
            if [[ "${DRY_RUN}" == true ]]; then
                log "INFO" "Would create: ${dir}"
            else
                mkdir -p "${dir}"
                log "DEBUG" "Created: ${dir}"
            fi
        fi
    done

    if [[ "${DRY_RUN}" != true ]]; then
        chmod 755 "${MRTG_BASE}"
        chmod 750 "${MRTG_CONF}"
        chmod 755 "${MRTG_LOG}"
        chmod 755 "${MRTG_HTML}"
        chmod 755 "${WEB_MRTG_DIR}"
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

    # Ensure SNMP is ready
    log "INFO" "Verifying SNMP is responsive..."
    sleep 2

    # Try cfgmaker with retries
    local cfg_success=false
    for i in {1..3}; do
        log "INFO" "Attempt ${i} to detect interfaces..."
        if timeout 30 ${cfgmaker_path} \
            --global "WorkDir: ${WEB_MRTG_DIR}" \
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
                # Check if it actually contains interface data
                if grep -q "Target\[" "${cfg_file}.tmp"; then
                    mv "${cfg_file}.tmp" "${cfg_file}"
                    cfg_success=true
                    log "SUCCESS" "Configuration generated with $(grep -c "Target\[" "${cfg_file}") interfaces"
                    break
                fi
            fi
        fi
        log "INFO" "Retrying in 2 seconds..."
        sleep 2
    done

    # Fallback to template
    if [[ "${cfg_success}" != true ]]; then
        log "WARNING" "cfgmaker failed - using template configuration"
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

# System Uptime
Target[uptime]: .1.3.6.1.2.1.1.3.0:${SNMP_COMMUNITY}@127.0.0.1:
Title[uptime]: System Uptime
PageTop[uptime]: <h1>System Uptime</h1>
MaxBytes[uptime]: 100000000
ShortLegend[uptime]: secs
YLegend[uptime]: Uptime (seconds)
Options[uptime]: growright, noinfo, nopercent

# System Processes
Target[processes]: .1.3.6.1.2.1.25.1.6.0:${SNMP_COMMUNITY}@127.0.0.1:
Title[processes]: System Processes
PageTop[processes]: <h1>Running Processes</h1>
MaxBytes[processes]: 1000
ShortLegend[processes]: procs
YLegend[processes]: Processes
Options[processes]: growright, nopercent

EOF

    log "SUCCESS" "Configuration saved to ${cfg_file}"
}

generate_template_config() {
    local cfg_file="$1"
    local interfaces=($(detect_network_interfaces))

    log "INFO" "Creating template for ${#interfaces[@]} interfaces"

    cat > "${cfg_file}" << EOF
########################################################################
# MRTG Template Configuration
# Generated: $(date)
# Interfaces: ${#interfaces[@]}
########################################################################

# Global settings
WorkDir: ${WEB_MRTG_DIR}
LogDir: ${MRTG_LOG}
Interval: ${INTERVAL}
Options[_]: growright, bits
EnableIPv6: yes
Language: english
WriteExpires: Yes
WithPeak[_]: wmy

# Global HTML
Title[^]: MRTG Network Monitor - $(hostname)
PageTop[^]: <h1>MRTG Network Monitor - $(hostname)</h1>
XSize[_]: 600
YSize[_]: 300

EOF

    # Add each interface
    for interface in "${interfaces[@]}"; do
        # Detect speed
        local speed=1000000  # Default 1Gbps in bytes
        if [[ -f "/sys/class/net/${interface}/speed" ]]; then
            local detected=$(cat "/sys/class/net/${interface}/speed" 2>/dev/null | grep -o '[0-9]*' || echo "1000")
            speed=$((detected * 1000000 / 8))
        fi

        # Get description
        local desc="${interface}"
        if command -v ethtool >/dev/null 2>&1; then
            desc=$(ethtool "${interface}" 2>/dev/null | grep "Description" | cut -d: -f2- | xargs || echo "${interface}")
        fi

        cat >> "${cfg_file}" << EOF
# Interface: ${interface}
Target[${interface}]: ${interface}:${SNMP_COMMUNITY}@127.0.0.1:
MaxBytes[${interface}]: ${speed}
Title[${interface}]: Traffic Analysis for ${interface}
PageTop[${interface}]: <h1>Traffic Analysis for ${interface}</h1>
YLegend[${interface}]: Bits per second
ShortLegend[${interface}]: b/s
Legend1[${interface}]: Incoming Traffic
Legend2[${interface}]: Outgoing Traffic
WithPeak[${interface}]: wmy

EOF
    done
}

setup_cron() {
    log "INFO" "Setting up cron (interval: ${INTERVAL} minutes)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would add cron: */${INTERVAL} * * * * ${MRTG_BIN}/run-mrtg.sh"
        return 0
    fi

    # Create runner script
    cat > "${MRTG_BIN}/run-mrtg.sh" << 'EOF'
#!/bin/bash
# MRTG Runner - Generated by MRTG Professional Suite

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

MRTG_CONF="'"${MRTG_CONF}"'"
MRTG_LOG="'"${MRTG_LOG}"'"
WEB_DIR="'"${WEB_MRTG_DIR}"'"
WEB_USER="'"${WEB_USER}"'"
WEB_GROUP="'"${WEB_GROUP}"'"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "${MRTG_LOG}/cron.log"
}

# Run MRTG (3 passes for rate calculation)
for i in {1..3}; do
    log_message "MRTG run $i/3"
    /usr/bin/mrtg "${MRTG_CONF}/mrtg.cfg" --logging "${MRTG_LOG}/mrtg.log" 2>&1 | while read line; do
        log_message "MRTG: $line"
    done
    sleep 1
done

# Generate index
log_message "Generating index"
/usr/bin/indexmaker "${MRTG_CONF}/mrtg.cfg" --output="${WEB_DIR}/index.html"

# Set permissions
chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_DIR}" 2>/dev/null || true
chmod -R 755 "${WEB_DIR}" 2>/dev/null || true

log_message "Cron run completed"
EOF

    chmod +x "${MRTG_BIN}/run-mrtg.sh"

    # Remove old cron entries
    crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab -

    # Add new cron
    (crontab -l 2>/dev/null || true; echo "# MRTG Monitoring - Added by MRTG Professional Suite v${SCRIPT_VERSION}") | crontab -
    (crontab -l 2>/dev/null; echo "*/${INTERVAL} * * * * ${MRTG_BIN}/run-mrtg.sh >/dev/null 2>&1") | crontab -

    log "SUCCESS" "Cron installed"
}

setup_web_access() {
    log "INFO" "Configuring web access..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure web access"
        return 0
    fi

    # Create symbolic link
    if [[ "${WEB_MRTG_DIR}" != "${MRTG_HTML}" ]]; then
        ln -sfn "${WEB_MRTG_DIR}" "${MRTG_HTML}"
    fi

    # Create .htaccess for Apache/LiteSpeed
    if [[ "${WEB_SERVER}" == "apache" ]] || [[ "${WEB_SERVER}" == "litespeed" ]] || [[ "${WEB_SERVER}" == "openlitespeed" ]]; then
        cat > "${WEB_MRTG_DIR}/.htaccess" << EOF
# MRTG Access Control
# Generated: $(date)

Order Deny,Allow
Deny from all
Allow from 127.0.0.1
Allow from ::1

# Allow local network (uncomment if needed)
# Allow from 192.168.0.0/16
# Allow from 10.0.0.0/8
# Allow from 172.16.0.0/12

<FilesMatch "\.(png|gif|jpg|jpeg|css|js)$">
    Order Allow,Deny
    Allow from all
</FilesMatch>
EOF
    fi

    # Create robots.txt
    cat > "${WEB_MRTG_DIR}/robots.txt" << EOF
User-agent: *
Disallow: /
EOF

    # =====================================================================
    # DirectAdmin Permission Persistence
    # diradmin must own files, but web server needs read access
    # =====================================================================
    if [[ "${PANEL_TYPE}" == "directadmin" ]]; then
        log "INFO" "Setting DirectAdmin-specific permissions"

        # Ensure diradmin owns everything
        if id diradmin >/dev/null 2>&1; then
            chown -R diradmin:diradmin "${WEB_MRTG_DIR}"
        fi

        # Set 755 on directory so web server can read
        chmod 755 "${WEB_MRTG_DIR}"

        # Set 644 on files
        find "${WEB_MRTG_DIR}" -type f -exec chmod 644 {} \;

        log "SUCCESS" "DirectAdmin permissions set"
    else
        # Standard permissions
        chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_MRTG_DIR}" 2>/dev/null || true
        chmod -R 755 "${WEB_MRTG_DIR}" 2>/dev/null || true
    fi

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

            # Plugin config
            cat > "${mrtg_plugin}/plugin.conf" << EOF
name=MRTG Network Monitor
version=${SCRIPT_VERSION}
desc=Enterprise network monitoring and bandwidth graphing
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
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .content { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        iframe { border: 1px solid #ddd; border-radius: 5px; background: white; width: 100%; height: 800px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MRTG Network Monitor</h1>
        <p>DirectAdmin Integration | Version ${SCRIPT_VERSION}</p>
    </div>
    <div class="content">
        <iframe src="/mrtg/" frameborder="0"></iframe>
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
            if [[ -d "/usr/local/apache/htdocs" ]]; then
                ln -sfn "${WEB_MRTG_DIR}" "/usr/local/apache/htdocs/mrtg"
                log "SUCCESS" "cPanel integration configured"
            fi
            ;;

        "plesk")
            if [[ -d "/var/www/vhosts/default/htdocs" ]]; then
                ln -sfn "${WEB_MRTG_DIR}" "/var/www/vhosts/default/htdocs/mrtg"
                log "SUCCESS" "Plesk integration configured"
            fi
            ;;
    esac
}

# =============================================================================
# CRITICAL: 3-PASS WARMUP FUNCTION
# MRTG needs 3 runs to calculate rates and create all necessary files
# =============================================================================
initialize_mrtg() {
    log "INFO" "Initializing MRTG data collection (3-pass warmup)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would run MRTG 3 times to seed data"
        return 0
    fi

    local mrtg_path=$(command -v mrtg || echo "/usr/bin/mrtg")
    local cfg_file="${MRTG_CONF}/mrtg.cfg"

    # Ensure directories exist
    mkdir -p "${MRTG_LOG}" "${WEB_MRTG_DIR}"

    # =====================================================================
    # CRITICAL: 3-pass warmup loop
    # First run creates .log files (may error)
    # Second run creates .old files (may error)
    # Third run calculates rates (should succeed)
    # =====================================================================
    for i in {1..3}; do
        log "INFO" "Warmup pass ${i}/3..."

        # Run MRTG and ignore errors (they're expected during warmup)
        if ! env LANG=C ${mrtg_path} "${cfg_file}" --logging "${MRTG_LOG}/mrtg.log" >/dev/null 2>&1; then
            log "INFO" "Pass ${i} completed (expected warnings ignored)"
        fi

        # Small delay between runs
        sleep 2
    done

    # Generate index page
    log "INFO" "Generating index page..."
    local indexmaker_path=$(command -v indexmaker || echo "/usr/bin/indexmaker")
    ${indexmaker_path} "${cfg_file}" --output="${WEB_MRTG_DIR}/index.html"

    # Set permissions
    if [[ "${PANEL_TYPE}" == "directadmin" ]]; then
        if id diradmin >/dev/null 2>&1; then
            chown -R diradmin:diradmin "${WEB_MRTG_DIR}"
        fi
        chmod 755 "${WEB_MRTG_DIR}"
        find "${WEB_MRTG_DIR}" -type f -exec chmod 644 {} \;
    else
        chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_MRTG_DIR}" 2>/dev/null || true
        chmod -R 755 "${WEB_MRTG_DIR}" 2>/dev/null || true
    fi

    log "SUCCESS" "Initialization complete - MRTG data seeded"
}

# =============================================================================
# HEALTH CHECK FUNCTIONS
# =============================================================================

verify_system_health() {
    log "INFO" "Running comprehensive health check..."

    local errors=0
    local warnings=0

    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}              MRTG SYSTEM HEALTH DIAGNOSTIC${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

    # 1. Installation Check
    echo -e "${BOLD}1. Installation${NC}"
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

    # 2. SNMP Service
    echo -e "\n${BOLD}2. SNMP Service${NC}"
    if systemctl is-active --quiet snmpd 2>/dev/null || service snmpd status 2>/dev/null | grep -q "running"; then
        echo -e "  ${GREEN}✓${NC} SNMP service running"
    else
        echo -e "  ${RED}✗${NC} SNMP service not running"
        ((errors++))
    fi

    # Test SNMP
    if command -v snmpget >/dev/null 2>&1; then
        if snmpget -v 2c -c "${SNMP_COMMUNITY}" -t 2 127.0.0.1 sysUpTime.0 >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} SNMP responding"
        else
            echo -e "  ${RED}✗${NC} SNMP not responding - check community string"
            ((errors++))
        fi
    fi

    # 3. Cron
    echo -e "\n${BOLD}3. Scheduled Tasks${NC}"
    if crontab -l 2>/dev/null | grep -q "run-mrtg.sh"; then
        local cron_line=$(crontab -l 2>/dev/null | grep "run-mrtg.sh" | head -1 | awk '{$1=$2=$3=$4=$5=""; print $0}' | xargs)
        echo -e "  ${GREEN}✓${NC} Cron job active"
    else
        echo -e "  ${RED}✗${NC} No cron job found"
        ((errors++))
    fi

    # 4. Data Collection
    echo -e "\n${BOLD}4. Data Collection${NC}"
    if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
        local log_size=$(stat -c%s "${MRTG_LOG}/mrtg.log" 2>/dev/null || stat -f%z "${MRTG_LOG}/mrtg.log" 2>/dev/null)
        local last_mod=$(stat -c%Y "${MRTG_LOG}/mrtg.log" 2>/dev/null || stat -f%m "${MRTG_LOG}/mrtg.log" 2>/dev/null)
        local current_time=$(date +%s)
        local minutes_ago=$(( (current_time - last_mod) / 60 ))

        echo -e "  ${GREEN}✓${NC} Log size: $(numfmt --to=iec ${log_size} 2>/dev/null || echo "${log_size} bytes")"

        if [[ ${minutes_ago} -le 10 ]]; then
            echo -e "  ${GREEN}✓${NC} Last update: ${minutes_ago} minutes ago"
        else
            echo -e "  ${YELLOW}⚠${NC} Last update: ${minutes_ago} minutes ago (stale)"
            ((warnings++))
        fi
    else
        echo -e "  ${RED}✗${NC} No log file found"
        ((errors++))
    fi

    # 5. Web Interface
    echo -e "\n${BOLD}5. Web Interface${NC}"
    if [[ -d "${WEB_MRTG_DIR}" ]]; then
        echo -e "  ${GREEN}✓${NC} Web directory exists"

        local image_count=$(find "${WEB_MRTG_DIR}" -name "*.png" 2>/dev/null | wc -l)
        if [[ ${image_count} -gt 0 ]]; then
            echo -e "  ${GREEN}✓${NC} Found ${image_count} graph images"
        else
            echo -e "  ${YELLOW}⚠${NC} No graphs yet (waiting for first data)"
            ((warnings++))
        fi

        if [[ -f "${WEB_MRTG_DIR}/index.html" ]]; then
            echo -e "  ${GREEN}✓${NC} Index page exists"
        else
            echo -e "  ${YELLOW}⚠${NC} Index page missing"
            ((warnings++))
        fi

        # Check permissions
        if [[ -r "${WEB_MRTG_DIR}" ]]; then
            echo -e "  ${GREEN}✓${NC} Directory is readable"
        else
            echo -e "  ${RED}✗${NC} Directory not readable"
            ((errors++))
        fi
    else
        echo -e "  ${RED}✗${NC} Web directory missing"
        ((errors++))
    fi

    # 6. Network Interfaces
    echo -e "\n${BOLD}6. Network Interfaces${NC}"
    local interfaces=($(detect_network_interfaces))
    echo -e "  ${GREEN}✓${NC} Detected ${#interfaces[@]} active interfaces"
    local monitored=0
    for interface in "${interfaces[@]}"; do
        if [[ -f "${WEB_MRTG_DIR}/${interface}.html" ]]; then
            monitored=$((monitored + 1))
        fi
    done
    echo -e "  ${GREEN}✓${NC} Monitoring ${monitored} interfaces"

    # 7. Firewall Status
    echo -e "\n${BOLD}7. Firewall Configuration${NC}"
    if [[ -f /etc/csf/csf.conf ]]; then
        if grep -q "161" /etc/csf/csf.conf; then
            echo -e "  ${GREEN}✓${NC} CSF allows SNMP (port 161)"
        else
            echo -e "  ${YELLOW}⚠${NC} CSF may block SNMP - port 161 not configured"
            ((warnings++))
        fi
    fi

    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}SUMMARY${NC}"
    echo -e "  Errors: ${errors}   Warnings: ${warnings}"

    if [[ ${errors} -eq 0 && ${warnings} -eq 0 ]]; then
        echo -e "\n${GREEN}${BOLD}✓ SYSTEM HEALTH: PERFECT${NC}"
    elif [[ ${errors} -eq 0 && ${warnings} -gt 0 ]]; then
        echo -e "\n${YELLOW}${BOLD}⚠ SYSTEM HEALTH: GOOD WITH WARNINGS${NC}"
    else
        echo -e "\n${RED}${BOLD}✗ SYSTEM HEALTH: ISSUES DETECTED${NC}"
        echo -e "${RED}Please fix the ${errors} error(s) above${NC}"
    fi

    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

    return ${errors}
}

repair_installation() {
    log "INFO" "Attempting repair..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would attempt repair"
        return 0
    fi

    # Backup first
    backup_config

    # Restart SNMP
    log "INFO" "Restarting SNMP..."
    if systemctl list-units --full -all 2>/dev/null | grep -q 'snmpd.service'; then
        systemctl restart snmpd
    else
        service snmpd restart
    fi
    sleep 3

    # Regenerate config
    generate_mrtg_config

    # Reinitialize with warmup
    initialize_mrtg

    # Fix cron if missing
    if ! crontab -l 2>/dev/null | grep -q "run-mrtg.sh"; then
        setup_cron
    fi

    # Fix permissions
    if [[ "${PANEL_TYPE}" == "directadmin" ]]; then
        if id diradmin >/dev/null 2>&1; then
            chown -R diradmin:diradmin "${WEB_MRTG_DIR}"
        fi
        chmod 755 "${WEB_MRTG_DIR}"
        find "${WEB_MRTG_DIR}" -type f -exec chmod 644 {} \;
    else
        chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_MRTG_DIR}" 2>/dev/null || true
        chmod -R 755 "${WEB_MRTG_DIR}" 2>/dev/null || true
    fi

    log "SUCCESS" "Repair completed"

    verify_system_health
}

# =============================================================================
# BACKUP FUNCTIONS
# =============================================================================

backup_config() {
    local backup_file="${BACKUP_DIR}/mrtg-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

    log "INFO" "Creating backup: ${backup_file}"

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would backup to: ${backup_file}"
        return 0
    fi

    mkdir -p "${BACKUP_DIR}"

    # Backup configuration
    tar -czf "${backup_file}" \
        --exclude="${MRTG_LOG}/*" \
        --exclude="${MRTG_VAR}/*" \
        "${MRTG_CONF}" \
        "${MRTG_BIN}" \
        /etc/snmp/snmpd.conf \
        2>/dev/null || true

    # Save info
    cat > "${BACKUP_DIR}/install-info.txt" << EOF
MRTG Backup
Date: $(date)
Version: ${SCRIPT_VERSION}
Web Server: ${WEB_SERVER}
Web User: ${WEB_USER}
Web Root: ${WEB_ROOT}
SNMP: ${SNMP_COMMUNITY}
Panel: ${PANEL_TYPE}
Interval: ${INTERVAL}
EOF

    log "SUCCESS" "Backup created: ${backup_file}"
    echo -e "${GREEN}Backup saved to: ${backup_file}${NC}"
}

restore_config() {
    log "INFO" "Available backups:"

    local backups=($(ls -1 "${BACKUP_DIR}"/*.tar.gz 2>/dev/null))

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

    if confirm_action "Restore from $(basename "${selected}")? This will overwrite current configuration."; then
        log "INFO" "Restoring from: ${selected}"

        # Backup current
        backup_config

        # Stop cron
        crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | crontab -

        # Restore
        tar -xzf "${selected}" -C /

        # Restart services
        systemctl restart snmpd 2>/dev/null || service snmpd restart 2>/dev/null || true
        sleep 3

        # Re-add cron
        setup_cron

        # Reinitialize
        initialize_mrtg

        log "SUCCESS" "Restore completed"
    fi
}

# =============================================================================
# UNINSTALL FUNCTIONS
# =============================================================================

uninstall_mrtg() {
    log "INFO" "Starting uninstall..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would perform uninstall"
        return 0
    fi

    if [[ "${FORCE_MODE}" != true ]]; then
        echo -e "${RED}${BOLD}WARNING: This will remove MRTG and all configurations${NC}"
        echo -e "Affected:"
        echo -e "  - ${MRTG_BASE}"
        echo -e "  - ${WEB_MRTG_DIR}"
        echo -e "  - /etc/snmp/snmpd.conf"
        echo -e "  - MRTG cron jobs"
        echo ""

        if ! confirm_action "Continue with uninstall?"; then
            log "INFO" "Uninstall cancelled"
            return 0
        fi
    fi

    # Backup
    backup_config

    # Remove cron
    log "INFO" "Removing cron..."
    crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab -

    # Remove DirectAdmin plugin
    if [[ -d "/usr/local/directadmin/plugins/mrtg-monitor" ]]; then
        log "INFO" "Removing DirectAdmin plugin..."
        rm -rf "/usr/local/directadmin/plugins/mrtg-monitor"
    fi

    # Remove packages?
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

    # Remove data?
    if confirm_action "Remove all MRTG data?"; then
        log "INFO" "Removing files..."
        rm -rf "${MRTG_BASE}"
        rm -rf "${MRTG_VAR}"
        rm -rf "${WEB_MRTG_DIR}"

        # Restore SNMP config?
        local snmp_backup=$(ls -1 /etc/snmp/snmpd.conf.backup.* 2>/dev/null | head -1)
        if [[ -n "${snmp_backup}" ]] && confirm_action "Restore original SNMP config?"; then
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
                 PROFESSIONAL MONITORING SUITE v${SCRIPT_VERSION}
================================================================================

This installer will:
  ✓ Detect your existing web server
  ✓ Configure secure SNMP monitoring
  ✓ Set up automatic data collection
  ✓ Integrate with your control panel
  ✓ NEVER modify your web server

EOF

    check_root
    acquire_lock
    detect_os
    detect_control_panel
    detect_web_server

    echo -e "\n${BOLD}Detected Configuration:${NC}"
    echo -e "  OS: ${GREEN}${OS_NAME} ${OS_VERSION}${NC}"
    echo -e "  Web Server: ${GREEN}${WEB_SERVER}${NC}"
    echo -e "  Web User: ${GREEN}${WEB_USER}${NC}"
    echo -e "  Web Directory: ${GREEN}${WEB_MRTG_DIR}${NC}"

    if [[ "${PANEL_TYPE}" != "none" ]]; then
        echo -e "  Control Panel: ${GREEN}${PANEL_TYPE}${NC}"
    fi

    echo -e "\n${BOLD}Configuration:${NC}"
    read -p "Monitoring interval in minutes [${DEFAULT_INTERVAL}]: " interval
    INTERVAL=${interval:-${DEFAULT_INTERVAL}}

    read -p "SNMP Community String [auto-generate]: " snmp_input
    SNMP_COMMUNITY=${snmp_input}

    read -p "Notification email [${DEFAULT_EMAIL}]: " email_input
    DEFAULT_EMAIL=${email_input:-${DEFAULT_EMAIL}}

    echo -e "\n${YELLOW}Summary:${NC}"
    echo -e "  Interval: ${INTERVAL} minutes"
    echo -e "  SNMP: ${SNMP_COMMUNITY:-"<auto-generated>"}"
    echo -e "  Email: ${DEFAULT_EMAIL}"
    echo ""

    if ! confirm_action "Proceed with installation?"; then
        log "INFO" "Installation cancelled"
        return 0
    fi

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

    # Save config
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

    local server_ip=$(detect_ip_address)
    echo -e "\n${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}                    INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

    echo -e "Access MRTG: ${BLUE}http://${server_ip}/mrtg/${NC}"
    echo -e "SNMP Community: ${YELLOW}${SNMP_COMMUNITY}${NC} (keep secure!)"
    echo -e "Configuration: ${CYAN}${MRTG_CONF}/mrtg.cfg${NC}"
    echo -e "Logs: ${CYAN}${MRTG_LOG}/mrtg.log${NC}\n"

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
                         Enterprise Edition v${SCRIPT_VERSION}
================================================================================

EOF

    echo -e "${BOLD}MAIN MENU${NC}\n"

    echo -e "  ${GREEN}1)${NC} Install MRTG (Full wizard)"
    echo -e "  ${GREEN}2)${NC} Uninstall MRTG"
    echo -e "  ${GREEN}3)${NC} Run Health Check"
    echo -e "  ${GREEN}4)${NC} Repair Installation"
    echo -e "  ${GREEN}5)${NC} Backup Configuration"
    echo -e "  ${GREEN}6)${NC} Restore from Backup"
    echo -e "  ${GREEN}7)${NC} Update Script"
    echo -e "  ${GREEN}8)${NC} Add/Update Cron"
    echo -e "  ${GREEN}9)${NC} Remove Cron"
    echo -e "  ${GREEN}10)${NC} View Logs"
    echo -e "  ${GREEN}11)${NC} Dry Run (Test Mode)"
    echo -e "  ${GREEN}0)${NC} Exit\n"

    read -p "Enter choice [0-11]: " choice

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
        7) self_update ;;
        8)
            detect_web_server
            read -p "Interval in minutes [${DEFAULT_INTERVAL}]: " interval
            INTERVAL=${interval:-${DEFAULT_INTERVAL}}
            setup_cron
            ;;
        9)
            if confirm_action "Remove MRTG cron?"; then
                crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab -
                log "SUCCESS" "Cron removed"
            fi
            ;;
        10)
            if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
                tail -50 "${MRTG_LOG}/mrtg.log"
            else
                log "ERROR" "Log not found"
            fi
            ;;
        11)
            DRY_RUN=true
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

${BOLD}OPTIONS${NC}
    --install, -i     Run installation wizard
    --uninstall, -u   Complete removal
    --status, -s      Health check
    --repair, -r      Fix common issues
    --backup, -b      Backup configuration
    --restore, -R     Restore from backup
    --update, -U      Self-update from GitHub
    --dry-run         Test without changes
    --force           Skip confirmations
    --version, -v     Show version
    --help, -h        Show this help

${BOLD}EXAMPLES${NC}
    ${SCRIPT_NAME} --install      # Install MRTG
    ${SCRIPT_NAME} --status       # Check health
    ${SCRIPT_NAME} --repair       # Fix issues
    ${SCRIPT_NAME} --update       # Update script
    ${SCRIPT_NAME} --uninstall    # Remove MRTG

${BOLD}FILES${NC}
    ${MRTG_BASE}         Installation
    ${MRTG_CONF}         Configuration
    ${MRTG_LOG}          Log files
    ${BACKUP_DIR}        Backups

${BOLD}AUTHOR${NC}
    Written by ${SCRIPT_AUTHOR}
    GitHub: https://github.com/waelisa/mrtg

EOF
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Create log file
    touch "${LOG_FILE}"
    chmod 644 "${LOG_FILE}"

    # Parse arguments
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
                backup_config
                ;;
            --restore|-R)
                check_root
                restore_config
                ;;
            --update|-U)
                check_root
                self_update
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
        show_menu
    fi
}

# Trap
trap 'rm -f "${LOCK_FILE}"' EXIT
trap 'error_exit "Interrupted on line $LINENO"' INT TERM

# Run
main "$@"
