#!/bin/bash
#
# MRTG Professional Monitoring Suite - Enterprise Edition v2.1.3
# Production-Hardened Network Monitoring for Hosting Environments
# The definitive MRTG installer for hosting environments
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
# Version:     v2.1.3
# Build Date:  02/27/2026
# License:     MIT
#
# DESCRIPTION:
#   The definitive MRTG installer for production hosting environments
#   - Zero-assumption architecture works with ANY existing setup
#   - Full DirectAdmin/cPanel/Plesk integration with native plugins
#   - Smart CSF firewall configuration with syntax safety
#   - 3-pass warmup with validation to eliminate first-run errors
#   - SNMP stabilization delay for slow servers
#   - Socket-aware service detection (MySQL, Rspamd, etc.)
#   - Process lockfile to prevent cron race conditions
#   - Automated log rotation to prevent disk exhaustion
#   - Timeout-protected Rspamd polling for busy mail servers
#   - Deep MySQL thread monitoring for connection analysis
#   - Auto-mode for unattended installations
#   - Nice/ionice CPU prioritization
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
#   --auto, -a        Unattended installation (uses defaults)
#   --dry-run         Test without changes
#   --force           Skip confirmations
#   --version, -v     Show version
#   --help, -h        Show this help
#
# =============================================================================

set -euo pipefail
set -E
IFS=$'\n\t'

# =============================================================================
# GLOBAL CONSTANTS
# =============================================================================

readonly SCRIPT_VERSION="v2.1.3"
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
readonly MRTG_SCRIPTS="${MRTG_BASE}/scripts"

# Default values
DEFAULT_INTERVAL=5
DEFAULT_EMAIL="root@localhost"
SNMP_COMMUNITY=""
SNMP_V3_USER=""
SNMP_V3_AUTH=""
SNMP_V3_PRIV=""
WEB_ROOT=""
WEB_USER=""
WEB_GROUP=""
WEB_SERVER="unknown"
PANEL_TYPE="none"
PANEL_VERSION="unknown"
HAS_RSPAMD=false
HAS_MYSQL=false
HAS_REDIS=false
HAS_EXIM=false
HAS_DOVECOT=false
MYSQL_SOCKET=""
INTERVAL=${DEFAULT_INTERVAL}
FORCE_MODE=false
DRY_RUN=false
AUTO_MODE=false
DEBUG=${DEBUG:-}  # Default DEBUG to empty string to avoid unbound variable

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
# ERROR HANDLING
# =============================================================================

# Trap any error to print line number and exit
trap 'error_handler $? $LINENO' ERR

error_handler() {
    local exit_code=$1
    local line_no=$2
    log "ERROR" "Script failed at line ${line_no} with exit code ${exit_code}"
    exit ${exit_code}
}

# =============================================================================
# UTILITY FUNCTIONS
#============================================================================

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
            "DEBUG")   [[ -n "${DEBUG:-}" ]] && echo -e "${MAGENTA}[DEBUG]${NC} ${message}" ;;
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

    if [[ "${FORCE_MODE}" == true ]] || [[ "${DRY_RUN}" == true ]] || [[ "${AUTO_MODE}" == true ]]; then
        return 0
    fi

    local response
    read -p "${prompt} (y/N): " response
    [[ "${response}" =~ ^[Yy]$ ]]
}

acquire_lock() {
    if [[ -f "${LOCK_FILE}" ]]; then
        local pid=$(cat "${LOCK_FILE}" 2>/dev/null || true)
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
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
        if command -v /usr/local/cpanel/cpanel >/dev/null 2>&1; then
            PANEL_VERSION=$(/usr/local/cpanel/cpanel -V 2>/dev/null | head -1 | tr -d ' ' || echo "unknown")
        fi
        log "SUCCESS" "cPanel detected (v${PANEL_VERSION})"

    # Plesk
    elif [[ -d /usr/local/psa ]]; then
        PANEL_TYPE="plesk"
        if command -v plesk >/dev/null 2>&1; then
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
        WEB_USER=$(ps aux | grep nginx | grep -v grep | head -1 | awk '{print $1}' || true)
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
        WEB_USER=$(ps aux | grep caddy | grep -v grep | head -1 | awk '{print $1}' || true)
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
            else
                WEB_ROOT="/var/www/html"
            fi
            ;;
        "cpanel")
            if [[ -d "/usr/local/apache/htdocs" ]]; then
                WEB_ROOT="/usr/local/apache/htdocs"
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
                    else
                        WEB_ROOT="/var/www/html"
                    fi
                    ;;
                "apache")
                    if [[ -d "/var/www/html" ]]; then
                        WEB_ROOT="/var/www/html"
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
                    WEB_ROOT="/var/www/html"
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

# =============================================================================
# SERVICE DETECTION FUNCTIONS
# =============================================================================

detect_rspamd() {
    log "INFO" "Checking for Rspamd email filter..."

    if command -v rspamd >/dev/null 2>&1; then
        # Check if service is running
        if systemctl is-active --quiet rspamd 2>/dev/null || pgrep rspamd >/dev/null 2>&1; then
            HAS_RSPAMD=true
            log "SUCCESS" "Rspamd detected and running"

            # =================================================================
            # CRITICAL: Ensure web user can access Rspamd socket
            # =================================================================
            if getent group rspamd >/dev/null 2>&1; then
                usermod -aG rspamd "${WEB_USER}" >/dev/null 2>&1 || true
                # Also add common service users
                for user in snmp snmpd www-data apache nginx nobody; do
                    if id "${user}" >/dev/null 2>&1; then
                        usermod -aG rspamd "${user}" >/dev/null 2>&1 || true
                    fi
                done
                log "DEBUG" "Added users to rspamd group for socket access"
            fi
        else
            HAS_RSPAMD=false
            log "INFO" "Rspamd installed but not running"
        fi
    else
        HAS_RSPAMD=false
        log "INFO" "Rspamd not detected"
    fi
}

detect_mysql_socket() {
    MYSQL_SOCKET=""

    # Method 1: Try mysql_config
    if command -v mysql_config >/dev/null 2>&1; then
        MYSQL_SOCKET=$(mysql_config --socket 2>/dev/null || true)
        if [[ -n "${MYSQL_SOCKET}" ]] && [[ -S "${MYSQL_SOCKET}" ]]; then
            log "DEBUG" "Found MySQL socket via mysql_config: ${MYSQL_SOCKET}"
            return 0
        fi
    fi

    # Method 2: Check common socket locations
    local socket_locations=(
        "/var/lib/mysql/mysql.sock"
        "/tmp/mysql.sock"
        "/var/run/mysqld/mysqld.sock"
        "/var/run/mysql/mysql.sock"
        "/var/lib/mysqld/mysqld.sock"
        "/var/run/mariadb/mariadb.sock"
        "/var/lib/mariadb/mariadb.sock"
    )

    for loc in "${socket_locations[@]}"; do
        if [[ -S "${loc}" ]]; then
            MYSQL_SOCKET="${loc}"
            log "DEBUG" "Found MySQL socket at: ${MYSQL_SOCKET}"
            return 0
        fi
    done

    # Method 3: Try to extract from running process
    if pgrep mysqld >/dev/null 2>&1; then
        local pid=$(pgrep mysqld | head -1 || true)
        if [[ -n "${pid}" ]]; then
            # Try to get socket from /proc
            MYSQL_SOCKET=$(ls -l /proc/${pid}/fd 2>/dev/null | grep socket | grep -o '/[^ ]*\.sock' | head -1 || true)
            if [[ -n "${MYSQL_SOCKET}" ]] && [[ -S "${MYSQL_SOCKET}" ]]; then
                log "DEBUG" "Found MySQL socket from process: ${MYSQL_SOCKET}"
                return 0
            fi
        fi
    fi

    # Method 4: Try MySQL client with connection
    if command -v mysql >/dev/null 2>&1; then
        local test_socket=$(mysql -e "SHOW VARIABLES LIKE 'socket'" 2>/dev/null | grep socket | awk '{print $2}' || true)
        if [[ -n "${test_socket}" ]] && [[ -S "${test_socket}" ]]; then
            MYSQL_SOCKET="${test_socket}"
            log "DEBUG" "Found MySQL socket from query: ${MYSQL_SOCKET}"
            return 0
        fi
    fi

    log "WARNING" "Could not find MySQL socket - will use TCP connection"
    MYSQL_SOCKET=""
    return 1
}

detect_mysql() {
    log "INFO" "Checking for MySQL/MariaDB..."

    if command -v mysql >/dev/null 2>&1; then
        # Check for running service
        if systemctl is-active --quiet mysql 2>/dev/null || \
           systemctl is-active --quiet mariadb 2>/dev/null || \
           pgrep mysqld >/dev/null 2>&1; then

            HAS_MYSQL=true
            log "SUCCESS" "MySQL/MariaDB detected"
            detect_mysql_socket || true  # ignore return, we just want to set socket
        fi
    fi
}

detect_redis() {
    log "INFO" "Checking for Redis..."

    if command -v redis-server >/dev/null 2>&1; then
        if systemctl is-active --quiet redis 2>/dev/null || \
           systemctl is-active --quiet redis-server 2>/dev/null || \
           pgrep redis-server >/dev/null 2>&1; then
            HAS_REDIS=true
            log "SUCCESS" "Redis detected"
        elif command -v redis-cli >/dev/null 2>&1 && redis-cli ping >/dev/null 2>&1; then
            HAS_REDIS=true
            log "SUCCESS" "Redis detected (responding to ping)"
        fi
    fi
}

detect_exim() {
    log "INFO" "Checking for Exim MTA..."

    if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
        if systemctl is-active --quiet exim 2>/dev/null || \
           systemctl is-active --quiet exim4 2>/dev/null || \
           pgrep exim >/dev/null 2>&1; then
            HAS_EXIM=true
            log "SUCCESS" "Exim detected"
        fi
    fi
}

detect_dovecot() {
    log "INFO" "Checking for Dovecot IMAP/POP3..."

    if command -v dovecot >/dev/null 2>&1 || command -v doveadm >/dev/null 2>&1; then
        if systemctl is-active --quiet dovecot 2>/dev/null || \
           pgrep dovecot >/dev/null 2>&1; then
            HAS_DOVECOT=true
            log "SUCCESS" "Dovecot detected"
        fi
    fi
}

detect_network_interfaces() {
    local interfaces=()

    # Get all active network interfaces
    if ls /sys/class/net/ >/dev/null 2>&1; then
        while IFS= read -r interface; do
            # Skip virtual interfaces
            if [[ ! "${interface}" =~ ^(lo|virbr|docker|veth|br-|tun|vnet) ]] && \
               ip link show "${interface}" 2>/dev/null | grep -q "UP"; then
                interfaces+=("${interface}")
            fi
        done < <(ls /sys/class/net/ 2>/dev/null || true)
    else
        while IFS= read -r line; do
            interface=$(echo "$line" | awk -F': ' '/^[0-9]+: / {print $2}' | cut -d@ -f1)
            if [[ -n "${interface}" && ! "${interface}" =~ ^(lo|virbr|docker|veth|br-|tun|vnet) ]]; then
                interfaces+=("${interface}")
            fi
        done < <(ip link show 2>/dev/null || true)
    fi

    # Fallback
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        while IFS= read -r interface; do
            if [[ "${interface}" != "lo" ]]; then
                interfaces+=("${interface}")
            fi
        done < <(ls /sys/class/net/ 2>/dev/null || true)
    fi

    printf '%s\n' "${interfaces[@]}"
}

detect_ip_address() {
    local ip=""

    # Try multiple methods
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip route get 1 2>/dev/null | awk '{print $NF;exit}' || true)
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
        log "INFO" "Would install: mrtg, snmpd, snmp, perl modules, python3"
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
                python3 \
                python3-json \
                curl \
                wget \
                --no-install-recommends || error_exit "Failed to install packages"
            ;;
        centos|rhel|almalinux|rocky|fedora)
            # Enable EPEL if needed
            if [[ "${OS_ID}" != "fedora" ]] && ! rpm -q epel-release >/dev/null 2>&1; then
                yum install -y -q epel-release || true
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
                ca-certificates \
                python3 \
                python3-json \
                curl \
                wget || error_exit "Failed to install packages"
            ;;
        *)
            log "WARNING" "Unknown OS, attempting generic installation"
            if command -v yum >/dev/null; then
                yum install -y mrtg net-snmp net-snmp-utils python3 curl wget || error_exit "Failed to install packages"
            elif command -v apt-get >/dev/null; then
                apt-get update && apt-get install -y mrtg snmpd snmp python3 curl wget || error_exit "Failed to install packages"
            else
                error_exit "Cannot install packages - unsupported package manager"
            fi
            ;;
    esac

    # Verify installations
    local missing=()
    for cmd in mrtg snmpd cfgmaker indexmaker python3; do
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
        cp /etc/snmp/snmpd.conf "/etc/snmp/snmpd.conf.backup.$(date +%Y%m%d-%H%M%S)" || true
    fi

    # Create base SNMP configuration
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
proc  rspamd 5 3
proc  redis 5 3
proc  exim 10 5
proc  dovecot 10 5

# Disk monitoring
includeAllDisks 10%

# Load averages
load 12 10 5

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
        systemctl restart snmpd || true
    else
        service snmpd restart || true
    fi

    # CRITICAL: Wait for SNMP to fully initialize
    log "INFO" "Waiting 5 seconds for SNMP service to stabilize..."
    sleep 5

    # Verify SNMP is working
    local max_attempts=5
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if command -v snmpwalk >/dev/null 2>&1; then
            if snmpwalk -v 2c -c "${SNMP_COMMUNITY}" -t 2 127.0.0.1 system 2>/dev/null | grep -q "sysName"; then
                log "SUCCESS" "SNMP verified and responding"
                break
            fi
        fi
        log "INFO" "Waiting for SNMP response (attempt ${attempt}/${max_attempts})..."
        sleep 2
        ((attempt++))
    done

    if [[ $attempt -gt $max_attempts ]]; then
        log "WARNING" "SNMP verification failed - check configuration manually"
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
        cp /etc/csf/csf.conf "/etc/csf/csf.conf.backup.$(date +%Y%m%d-%H%M%S)" || true

        local csf_modified=false

        # Process UDP_IN and UDP_OUT safely
        for port_type in "UDP_IN" "UDP_OUT"; do
            # Check if port 161 is already present
            if ! grep -q "161" /etc/csf/csf.conf; then
                # Get current value safely
                local current_line=$(grep "^${port_type} =" /etc/csf/csf.conf | head -1 || true)
                local current=$(echo "${current_line}" | cut -d'"' -f2 || true)

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
            csf -r >/dev/null 2>&1 || true
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
            firewall-cmd --permanent --add-service=snmp || true
            firewall-cmd --reload >/dev/null || true
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
            ufw allow snmp >/dev/null 2>&1 || true
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
            iptables -A INPUT -p udp --dport 161 -s 127.0.0.1 -j ACCEPT || true
            iptables -A INPUT -p udp --dport 161 -m state --state NEW -j ACCEPT || true
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
        "${MRTG_SCRIPTS}"
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
        chmod 755 "${MRTG_BASE}" 2>/dev/null || true
        chmod 750 "${MRTG_CONF}" 2>/dev/null || true
        chmod 755 "${MRTG_LOG}" 2>/dev/null || true
        chmod 755 "${MRTG_HTML}" 2>/dev/null || true
        chmod 755 "${MRTG_SCRIPTS}" 2>/dev/null || true
        chmod 755 "${WEB_MRTG_DIR}" 2>/dev/null || true
    fi

    log "SUCCESS" "Directories created"
}

# =============================================================================
# RSPAMD MONITORING SETUP (with timeout protection and robust JSON parsing)
# =============================================================================
setup_rspamd_monitoring() {
    if [[ "${HAS_RSPAMD}" != true ]] || [[ "${DRY_RUN}" == true ]]; then
        return 0
    fi

    log "INFO" "Setting up Rspamd monitoring helpers with timeout protection..."

    # Create the Rspamd stats helper script with robust JSON parsing
    cat > "${MRTG_SCRIPTS}/get_rspamd_stats.sh" << 'EOF'
#!/bin/bash
# Rspamd Statistics Collector for MRTG v2.1.3
# Handles timeouts, permissions, and malformed JSON gracefully

# Query with 2-second timeout to prevent hanging
STATS=$(timeout 2 rspamc -j stat 2>/dev/null)

if [[ $? -eq 0 ]] && [[ -n "$STATS" ]]; then
    # Parse JSON with fallback to zeros on any error
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    scanned = data.get('scanned', 0)
    rejected = data.get('actions', {}).get('reject', 0)
    print(scanned)
    print(rejected)
except:
    print('0')
    print('0')
" <<< "$STATS" 2>/dev/null || echo -e "0\n0"
else
    # Check if rspamd socket exists but we can't connect
    if [[ -S /var/run/rspamd/rspamd.sock ]] || [[ -S /tmp/rspamd.sock ]]; then
        # Socket exists but connection failed - likely permission issue
        echo "0"
        echo "0"
    else
        # No socket at all - rspamd probably not running
        echo "0"
        echo "0"
    fi
fi
EOF

    chmod 755 "${MRTG_SCRIPTS}/get_rspamd_stats.sh"

    # =====================================================================
    # CRITICAL: Fix Rspamd socket permissions
    # =====================================================================
    if [[ -d /var/run/rspamd ]]; then
        chmod 755 /var/run/rspamd 2>/dev/null || true
        chown -R rspamd:rspamd /var/run/rspamd 2>/dev/null || true
    fi

    # For systemd systems, create drop-in for socket permissions
    if command -v systemctl >/dev/null 2>&1 && [[ -f /etc/systemd/system/rspamd.service ]]; then
        mkdir -p /etc/systemd/system/rspamd.service.d 2>/dev/null || true
        cat > /etc/systemd/system/rspamd.service.d/override.conf << EOF
[Service]
SupplementaryGroups=rspamd
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl restart rspamd 2>/dev/null || true
        log "DEBUG" "Created systemd drop-in for rspamd socket permissions"
    fi

    log "SUCCESS" "Rspamd monitoring helpers installed with timeout protection"
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

    # =====================================================================
    # Add System Monitoring
    # =====================================================================
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

    # =====================================================================
    # RSPAMD MONITORING
    # =====================================================================
    if [[ "${HAS_RSPAMD}" == true ]]; then
        log "INFO" "Adding Rspamd monitoring to configuration..."

        cat >> "${cfg_file}" << EOF

########################################################################
# Rspamd Email Filter Monitoring
########################################################################
Target[rspamd]: \`${MRTG_SCRIPTS}/get_rspamd_stats.sh\`
Title[rspamd]: Rspamd Mail Filter Statistics
PageTop[rspamd]: <h1>Rspamd: Scanned vs Rejected</h1>
MaxBytes[rspamd]: 1000000
ShortLegend[rspamd]: msgs
YLegend[rspamd]: Messages
Legend1[rspamd]: Scanned (Total)
Legend2[rspamd]: Rejected (Spam)
Options[rspamd]: growright, nopercent, gauge
EOF
    fi

    # =====================================================================
    # MYSQL MONITORING (Socket-Aware with Thread Metrics)
    # =====================================================================
    if [[ "${HAS_MYSQL}" == true ]]; then
        log "INFO" "Adding MySQL monitoring to configuration..."

        # Build MySQL command with socket if available
        local mysql_cmd="mysql"
        local mysqladmin_cmd="mysqladmin"
        if [[ -n "${MYSQL_SOCKET}" ]]; then
            mysql_cmd="mysql --socket=${MYSQL_SOCKET}"
            mysqladmin_cmd="mysqladmin --socket=${MYSQL_SOCKET}"
            log "INFO" "Using MySQL socket: ${MYSQL_SOCKET}"
        fi

        cat >> "${cfg_file}" << EOF

########################################################################
# MySQL Database Monitoring - Query Statistics
########################################################################
Target[mysql]: \`${mysql_cmd} -e "show global status like 'Questions';" -N 2>/dev/null | awk '{print \$2}' || echo 0; ${mysql_cmd} -e "show global status like 'Slow_queries';" -N 2>/dev/null | awk '{print \$2}' || echo 0\`
Title[mysql]: MySQL Queries
PageTop[mysql]: <h1>MySQL: Total vs Slow Queries</h1>
MaxBytes[mysql]: 10000000
ShortLegend[mysql]: queries
YLegend[mysql]: Queries
Legend1[mysql]: Total Queries
Legend2[mysql]: Slow Queries
Options[mysql]: growright, nopercent, gauge

########################################################################
# MySQL Connection Thread Monitoring
########################################################################
Target[mysql_conns]: \`${mysqladmin_cmd} status 2>/dev/null | awk '{print \$4; print \$10}' || echo "0\n0"\`
Title[mysql_conns]: MySQL Connections vs Running
PageTop[mysql_conns]: <h1>MySQL Connection Threads</h1>
MaxBytes[mysql_conns]: 5000
ShortLegend[mysql_conns]: conns
YLegend[mysql_conns]: Connections
Legend1[mysql_conns]: Total Connections
Legend2[mysql_conns]: Running Threads
Options[mysql_conns]: growright, nopercent, gauge
EOF
    fi

    # =====================================================================
    # REDIS MONITORING
    # =====================================================================
    if [[ "${HAS_REDIS}" == true ]]; then
        log "INFO" "Adding Redis monitoring to configuration..."

        cat >> "${cfg_file}" << EOF

########################################################################
# Redis Cache Monitoring
########################################################################
Target[redis]: \`redis-cli info 2>/dev/null | grep -E '^(total_commands_processed|expired_keys):' | cut -d: -f2 | tr '\n' ' ' || echo "0 0"\`
Title[redis]: Redis Commands vs Expired Keys
PageTop[redis]: <h1>Redis Cache Statistics</h1>
MaxBytes[redis]: 10000000
ShortLegend[redis]: ops
YLegend[redis]: Operations
Legend1[redis]: Total Commands
Legend2[redis]: Expired Keys
Options[redis]: growright, nopercent, gauge
EOF
    fi

    # =====================================================================
    # EXIM MONITORING
    # =====================================================================
    if [[ "${HAS_EXIM}" == true ]]; then
        log "INFO" "Adding Exim monitoring to configuration..."

        cat >> "${cfg_file}" << EOF

########################################################################
# Exim Mail Queue Monitoring
########################################################################
Target[exim_queue]: \`exim -bpc 2>/dev/null || echo 0; exim -bp 2>/dev/null | grep -c '<' || echo 0\`
Title[exim_queue]: Exim Mail Queue
PageTop[exim_queue]: <h1>Exim Mail Queue</h1>
MaxBytes[exim_queue]: 10000
ShortLegend[exim_queue]: msgs
YLegend[exim_queue]: Messages
Legend1[exim_queue]: Frozen Messages
Legend2[exim_queue]: Total Queue
Options[exim_queue]: growright, nopercent, gauge
EOF
    fi

    # =====================================================================
    # DOVECOT MONITORING
    # =====================================================================
    if [[ "${HAS_DOVECOT}" == true ]]; then
        log "INFO" "Adding Dovecot monitoring to configuration..."

        # Check if doveadm is available
        if command -v doveadm >/dev/null 2>&1; then
            cat >> "${cfg_file}" << EOF

########################################################################
# Dovecot IMAP/POP3 Monitoring
########################################################################
Target[dovecot]: \`doveadm stats dump user 2>/dev/null | awk '{sum+=\$2} END {print sum}' || echo 0; doveadm stats dump user 2>/dev/null | awk '{sum+=\$3} END {print sum}' || echo 0\`
Title[dovecot]: Dovecot Connections
PageTop[dovecot]: <h1>Dovecot IMAP/POP3 Connections</h1>
MaxBytes[dovecot]: 1000
ShortLegend[dovecot]: conn
YLegend[dovecot]: Connections
Legend1[dovecot]: Active Connections
Legend2[dovecot]: Total Sessions
Options[dovecot]: growright, nopercent, gauge
EOF
        fi
    fi

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

# =============================================================================
# CRITICAL: LOGROTATE CONFIGURATION
# =============================================================================
setup_logrotate() {
    log "INFO" "Configuring log rotation for MRTG logs..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure logrotate for ${MRTG_LOG}"
        return 0
    fi

    cat > /etc/logrotate.d/mrtg << EOF
${MRTG_LOG}/*.log {
    weekly
    missingok
    rotate 4
    compress
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        # Restart MRTG if needed (though it's cron-based)
        [ -f /var/run/mrtg_cron.lock ] && rm -f /var/run/mrtg_cron.lock
    endscript
}
EOF

    log "SUCCESS" "Logrotate configured for MRTG logs"
}

# =============================================================================
# CRITICAL: CRON SETUP WITH LOCKFILE TO PREVENT RACE CONDITIONS
# =============================================================================
setup_cron() {
    log "INFO" "Setting up cron with lockfile protection (interval: ${INTERVAL} minutes)..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would add cron: */${INTERVAL} * * * * ${MRTG_BIN}/run-mrtg.sh"
        return 0
    fi

    # Create runner script with lockfile to prevent overlapping executions
    # Using unquoted EOF to allow variables to expand during installation
    # All runner-specific variables are escaped with backslash
    cat > "${MRTG_BIN}/run-mrtg.sh" << EOF
#!/bin/bash
# MRTG Runner - Generated by MRTG Professional Suite v2.1.3
# Includes lockfile to prevent race conditions on high-traffic servers

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

MRTG_CONF="${MRTG_CONF}"
MRTG_LOG="${MRTG_LOG}"
WEB_DIR="${WEB_MRTG_DIR}"
WEB_USER="${WEB_USER}"
WEB_GROUP="${WEB_GROUP}"

LOCKFILE="/tmp/mrtg_cron.lock"
LOGFILE="\${MRTG_LOG}/cron.log"

log_message() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\${LOGFILE}"
}

# Function to check if process is really running
is_process_running() {
    local pid=\$1
    if [[ -d "/proc/\${pid}" ]] && kill -0 "\${pid}" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Check if another instance is running
if [[ -f "\${LOCKFILE}" ]]; then
    pid=\$(cat "\${LOCKFILE}" 2>/dev/null || true)
    if [[ -n "\${pid}" ]] && is_process_running "\${pid}"; then
        log_message "Previous MRTG instance still running (PID: \${pid}). Exiting to prevent data corruption."
        exit 1
    else
        log_message "Removing stale lockfile from PID \${pid}"
        rm -f "\${LOCKFILE}"
    fi
fi

# Create lockfile with current PID
echo \$$ > "\${LOCKFILE}"
trap 'rm -f "\${LOCKFILE}"' EXIT

log_message "Starting MRTG run (with nice/ionice for low priority)"

# Run MRTG (3 passes for rate calculation) with low CPU priority
for i in {1..3}; do
    log_message "MRTG pass \$i/3"
    nice -n 19 ionice -c 3 /usr/bin/mrtg "\${MRTG_CONF}/mrtg.cfg" --logging "\${MRTG_LOG}/mrtg.log" 2>&1 | while read line; do
        log_message "MRTG: \$line"
    done
    sleep 1
done

# Generate index
log_message "Generating index"
nice -n 19 /usr/bin/indexmaker "\${MRTG_CONF}/mrtg.cfg" --output="\${WEB_DIR}/index.html"

# Verify index was generated correctly
if [[ -f "\${WEB_DIR}/index.html" ]] && grep -q "MRTG" "\${WEB_DIR}/index.html" 2>/dev/null; then
    log_message "Index page verified"
else
    log_message "WARNING: Index page may be incomplete"
fi

# Set permissions
chown -R "\${WEB_USER}:\${WEB_GROUP}" "\${WEB_DIR}" 2>/dev/null || true
chmod -R 755 "\${WEB_DIR}" 2>/dev/null || true

log_message "Cron run completed"
EOF

    chmod +x "${MRTG_BIN}/run-mrtg.sh"

    # Remove old cron entries
    crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab - || true

    # Add new cron
    (crontab -l 2>/dev/null || true; echo "# MRTG Monitoring - Added by MRTG Professional Suite v${SCRIPT_VERSION}") | crontab - || true
    (crontab -l 2>/dev/null; echo "*/${INTERVAL} * * * * ${MRTG_BIN}/run-mrtg.sh >/dev/null 2>&1") | crontab - || true

    log "SUCCESS" "Cron installed with lockfile protection and low CPU priority"
}

setup_web_access() {
    log "INFO" "Configuring web access..."

    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "Would configure web access"
        return 0
    fi

    # Create symbolic link
    if [[ "${WEB_MRTG_DIR}" != "${MRTG_HTML}" ]]; then
        ln -sfn "${WEB_MRTG_DIR}" "${MRTG_HTML}" 2>/dev/null || true
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
    # Apache alias configuration (ensures /mrtg always works)
    # =====================================================================
    if [[ "${WEB_SERVER}" == "apache" ]] && [[ -d /etc/apache2/conf-available || -d /etc/httpd/conf.d ]]; then
        if [[ -d /etc/apache2/conf-available ]]; then
            # Debian/Ubuntu
            cat > /etc/apache2/conf-available/mrtg.conf << EOF
Alias /mrtg ${WEB_MRTG_DIR}
<Directory ${WEB_MRTG_DIR}>
    Require local
    Options Indexes FollowSymLinks
</Directory>
EOF
            a2enconf mrtg >/dev/null 2>&1 || true
            systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null || true
        elif [[ -d /etc/httpd/conf.d ]]; then
            # RHEL/CentOS
            cat > /etc/httpd/conf.d/mrtg.conf << EOF
Alias /mrtg ${WEB_MRTG_DIR}
<Directory ${WEB_MRTG_DIR}>
    Require local
    Options Indexes FollowSymLinks
</Directory>
EOF
            systemctl reload httpd 2>/dev/null || service httpd reload 2>/dev/null || true
        fi
        log "SUCCESS" "Apache alias configured for /mrtg"
    fi

    # =====================================================================
    # DirectAdmin Permission Persistence
    # =====================================================================
    if [[ "${PANEL_TYPE}" == "directadmin" ]]; then
        log "INFO" "Setting DirectAdmin-specific permissions"

        # Ensure diradmin owns everything
        if id diradmin >/dev/null 2>&1; then
            chown -R diradmin:diradmin "${WEB_MRTG_DIR}" 2>/dev/null || true
        fi

        # Set 755 on directory so web server can read
        chmod 755 "${WEB_MRTG_DIR}" 2>/dev/null || true

        # Set 644 on files
        find "${WEB_MRTG_DIR}" -type f -exec chmod 644 {} \; 2>/dev/null || true

        log "SUCCESS" "DirectAdmin permissions set"
    else
        # Standard permissions
        chown -R "${WEB_USER}:${WEB_GROUP}" "${WEB_MRTG_DIR}" 2>/dev/null || true
        chmod -R 755 "${WEB_MRTG_DIR}" 2>/dev/null || true
    fi

    log "SUCCESS" "Web access configured"
}

# =============================================================================
# DIRECTADMIN PLUGIN INTEGRATION (with native plugin structure)
# =============================================================================
configure_panel_integration() {
    if [[ "${PANEL_TYPE}" == "none" ]] || [[ "${DRY_RUN}" == true ]]; then
        return 0
    fi

    log "INFO" "Configuring ${PANEL_TYPE} integration..."

    case "${PANEL_TYPE}" in
        "directadmin")
            local da_plugins="/usr/local/directadmin/plugins"
            local mrtg_plugin="${da_plugins}/mrtg"

            mkdir -p "${mrtg_plugin}/admin" "${mrtg_plugin}/data" "${mrtg_plugin}/hooks" "${mrtg_plugin}/images" 2>/dev/null || true

            # =================================================================
            # CRITICAL: DirectAdmin plugin.conf with all required flags
            # =================================================================
            cat > "${mrtg_plugin}/plugin.conf" << EOF
# DirectAdmin Plugin Configuration
# Generated by MRTG Professional Suite v${SCRIPT_VERSION}

name=MRTG Suite
id=mrtg
version=${SCRIPT_VERSION}
desc=Enterprise network monitoring with service detection
url=/plugins/mrtg/admin/
icon=images/mrtg_icon.png
level=admin
category=admin
active=yes
installed=yes
author=${SCRIPT_AUTHOR}
update_url=${REPO_URL}
EOF

            # Create a simple icon (base64 encoded 1x1 transparent PNG as fallback)
            cat > "${mrtg_plugin}/images/mrtg_icon.png" << 'EOF'
iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAAdgAAAHYBTsfm/wAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAH2SURBVDiNjZI9T9tQFIaf6+vYxIQECQhRNyhSpC5dmjIUqUtXJP6A/AJ26V/oxA9AomN3FrZ27MxWqRIDDEh8fM+xS0mI05E+0zvdc86rI0op/ie01uRyOQqFAq1Wi/PzcxRFUVVV5ubmaDab+L7P8PAw4+PjFAoF5ufnkVJyf3/P4eEhuVyO1dVVFhYWODw8ZGdnh1gsRiqVYnFxkXq9TqPRoNFo4DgOnU6HWCxGpVLBMAx838d1XUqlEpeXl+zv79NqtQjDkFwux9LSErOzs5yenlKpVEgkEjQaDWzbJp1Oo5RidHSUWCyGbdvkcjlarRaWZXF7e4vnebTbbdrtNvl8nqGhIaSUlMtlPM9jYmKCUqnE0dERjuMQRRGWZTE1NcXDwwMnJyek02l832d8fJzh4WFUVVEUheF4HIZh4DgOc3NzxONxXNel2WxSKBRoNpsUi0Vs26ZQKHB2doaUklgshlIKrTVaa6SUWJZFrVYjDENs2yaTyRBFEaOjo0RRRBRF+L7P6OgojuMQhiFaa4QQQoUQQgghhBAiBEEghBAiCIIwjmMhYowxQggBICJExBhjjDHGmBACEMYYI4QQQggBEEL8W1EUhRBCiP8uiiIhhBARQggRhqEQQkQIIUSE1loopYQQQkQppXAcB8dxSCaT+L6P1hrHcUgmk7iui1IKz/NIJpO4rovWmpubG6anp3l+fiYIAkZHR0kmk7iuS6vVYnJykvbLC+fn57TbbTzPY2hoiEKhQKvV4ubmhv8Ck0dn3scT1hQAAAAASUVORK5CYII=
EOF

            # Create plugin admin page with service detection
            cat > "${mrtg_plugin}/admin/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>MRTG Network Monitor</title>
    <meta http-equiv="refresh" content="300">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }
        .stat-box { background: white; padding: 15px; border-radius: 5px; flex: 1 1 200px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .stat-box h3 { margin: 0 0 10px 0; color: #666; font-size: 14px; }
        .stat-box .value { font-size: 24px; font-weight: bold; color: #667eea; }
        .content { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        iframe { border: 1px solid #ddd; border-radius: 5px; background: white; width: 100%; height: 800px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MRTG Network Monitor</h1>
        <p>DirectAdmin Integration | Version ${SCRIPT_VERSION}</p>
    </div>

    <div class="stats">
EOF

            # Add dynamic service status boxes
            if [[ "${HAS_RSPAMD}" == true ]]; then
                cat >> "${mrtg_plugin}/admin/index.html" << EOF
        <div class="stat-box">
            <h3>Rspamd Email Filter</h3>
            <div class="value">Active</div>
        </div>
EOF
            fi

            if [[ "${HAS_MYSQL}" == true ]]; then
                cat >> "${mrtg_plugin}/admin/index.html" << EOF
        <div class="stat-box">
            <h3>MySQL/MariaDB</h3>
            <div class="value">Active</div>
        </div>
EOF
            fi

            if [[ "${HAS_REDIS}" == true ]]; then
                cat >> "${mrtg_plugin}/admin/index.html" << EOF
        <div class="stat-box">
            <h3>Redis Cache</h3>
            <div class="value">Active</div>
        </div>
EOF
            fi

            cat >> "${mrtg_plugin}/admin/index.html" << EOF
    </div>

    <div class="content">
        <iframe src="/mrtg/" frameborder="0"></iframe>
    </div>
</body>
</html>
EOF

            # Set proper ownership for DirectAdmin
            if id diradmin >/dev/null 2>&1; then
                chown -R diradmin:diradmin "${mrtg_plugin}" 2>/dev/null || true
                chmod 755 "${mrtg_plugin}" 2>/dev/null || true
                chmod 644 "${mrtg_plugin}/plugin.conf" 2>/dev/null || true
            fi

            log "SUCCESS" "DirectAdmin plugin installed with native structure"
            ;;

        "cpanel")
            if [[ -d "/usr/local/apache/htdocs" ]]; then
                ln -sfn "${WEB_MRTG_DIR}" "/usr/local/apache/htdocs/mrtg" 2>/dev/null || true
                log "SUCCESS" "cPanel integration configured"
            fi
            ;;

        "plesk")
            if [[ -d "/var/www/vhosts/default/htdocs" ]]; then
                ln -sfn "${WEB_MRTG_DIR}" "/var/www/vhosts/default/htdocs/mrtg" 2>/dev/null || true
                log "SUCCESS" "Plesk integration configured"
            fi
            ;;
    esac
}

# =============================================================================
# CRITICAL: 3-PASS WARMUP FUNCTION WITH VALIDATION
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
    ${indexmaker_path} "${cfg_file}" --output="${WEB_MRTG_DIR}/index.html" 2>/dev/null || true

    # =====================================================================
    # CRITICAL: Verify index page was generated correctly
    # =====================================================================
    if [[ -f "${WEB_MRTG_DIR}/index.html" ]] && grep -q "MRTG" "${WEB_MRTG_DIR}/index.html" 2>/dev/null; then
        log "SUCCESS" "Index page verified - contains MRTG content"
    else
        log "WARNING" "Index page may be incomplete - check configuration"
    fi

    # Set permissions
    if [[ "${PANEL_TYPE}" == "directadmin" ]]; then
        if id diradmin >/dev/null 2>&1; then
            chown -R diradmin:diradmin "${WEB_MRTG_DIR}" 2>/dev/null || true
        fi
        chmod 755 "${WEB_MRTG_DIR}" 2>/dev/null || true
        find "${WEB_MRTG_DIR}" -type f -exec chmod 644 {} \; 2>/dev/null || true
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

    # 3. Cron with Lockfile
    echo -e "\n${BOLD}3. Scheduled Tasks${NC}"
    if crontab -l 2>/dev/null | grep -q "run-mrtg.sh"; then
        local cron_line=$(crontab -l 2>/dev/null | grep "run-mrtg.sh" | head -1 | awk '{$1=$2=$3=$4=$5=""; print $0}' | xargs)
        echo -e "  ${GREEN}✓${NC} Cron job active with lockfile protection"

        # Check if lockfile mechanism is working
        if [[ -f "/tmp/mrtg_cron.lock" ]]; then
            local lock_pid=$(cat "/tmp/mrtg_cron.lock" 2>/dev/null || true)
            if [[ -n "${lock_pid}" ]] && kill -0 "${lock_pid}" 2>/dev/null; then
                echo -e "  ${GREEN}✓${NC} Lockfile active (PID: ${lock_pid})"
            fi
        fi
    else
        echo -e "  ${RED}✗${NC} No cron job found"
        ((errors++))
    fi

    # 4. Logrotate Configuration
    echo -e "\n${BOLD}4. Log Maintenance${NC}"
    if [[ -f /etc/logrotate.d/mrtg ]]; then
        echo -e "  ${GREEN}✓${NC} Logrotate configured for MRTG logs"
    else
        echo -e "  ${YELLOW}⚠${NC} Logrotate not configured"
        ((warnings++))
    fi

    # 5. Data Collection
    echo -e "\n${BOLD}5. Data Collection${NC}"
    if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
        local log_size=$(stat -c%s "${MRTG_LOG}/mrtg.log" 2>/dev/null || stat -f%z "${MRTG_LOG}/mrtg.log" 2>/dev/null || echo "0")
        local last_mod=$(stat -c%Y "${MRTG_LOG}/mrtg.log" 2>/dev/null || stat -f%m "${MRTG_LOG}/mrtg.log" 2>/dev/null || echo "$(date +%s)")
        local current_time=$(date +%s)
        local minutes_ago=$(( (current_time - last_mod) / 60 ))

        if [[ ${log_size} -eq 0 ]]; then
            echo -e "  ${YELLOW}⚠${NC} Log file is empty - SNMP may be blocked by firewall"
            ((warnings++))
        else
            echo -e "  ${GREEN}✓${NC} Log size: $(numfmt --to=iec ${log_size} 2>/dev/null || echo "${log_size} bytes")"
        fi

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

    # 6. Web Interface
    echo -e "\n${BOLD}6. Web Interface${NC}"
    if [[ -d "${WEB_MRTG_DIR}" ]]; then
        echo -e "  ${GREEN}✓${NC} Web directory exists"

        local image_count=$(find "${WEB_MRTG_DIR}" -name "*.png" 2>/dev/null | wc -l || echo "0")
        if [[ ${image_count} -gt 0 ]]; then
            echo -e "  ${GREEN}✓${NC} Found ${image_count} graph images"
        else
            echo -e "  ${YELLOW}⚠${NC} No graphs yet (waiting for first data)"
            ((warnings++))
        fi

        if [[ -f "${WEB_MRTG_DIR}/index.html" ]]; then
            echo -e "  ${GREEN}✓${NC} Index page exists"

            # Verify index content
            if grep -q "MRTG" "${WEB_MRTG_DIR}/index.html" 2>/dev/null; then
                echo -e "  ${GREEN}✓${NC} Index page contains valid MRTG content"
            else
                echo -e "  ${YELLOW}⚠${NC} Index page may be invalid"
                ((warnings++))
            fi
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

    # 7. Network Interfaces
    echo -e "\n${BOLD}7. Network Interfaces${NC}"
    local interfaces=($(detect_network_interfaces))
    echo -e "  ${GREEN}✓${NC} Detected ${#interfaces[@]} active interfaces"
    local monitored=0
    for interface in "${interfaces[@]}"; do
        if [[ -f "${WEB_MRTG_DIR}/${interface}.html" ]]; then
            monitored=$((monitored + 1))
        fi
    done
    echo -e "  ${GREEN}✓${NC} Monitoring ${monitored} interfaces"

    # 8. Rspamd Check
    if [[ "${HAS_RSPAMD}" == true ]]; then
        echo -e "\n${BOLD}8. Rspamd Email Filter${NC}"
        if systemctl is-active --quiet rspamd 2>/dev/null || pgrep rspamd >/dev/null; then
            echo -e "  ${GREEN}✓${NC} Rspamd service running"

            # Test Rspamd stats collection with timeout
            if [[ -x "${MRTG_SCRIPTS}/get_rspamd_stats.sh" ]]; then
                local rspamd_test=$(timeout 3 "${MRTG_SCRIPTS}/get_rspamd_stats.sh" 2>/dev/null)
                if [[ -n "${rspamd_test}" ]] && echo "${rspamd_test}" | grep -q '^[0-9]\+'; then
                    echo -e "  ${GREEN}✓${NC} Rspamd stats collecting (timeout-protected)"

                    # Check if user is in rspamd group
                    if id "${WEB_USER}" 2>/dev/null | grep -q rspamd; then
                        echo -e "  ${GREEN}✓${NC} ${WEB_USER} has rspamd group access"
                    fi
                else
                    echo -e "  ${YELLOW}⚠${NC} Rspamd stats unavailable - check socket permissions"
                    ((warnings++))
                fi
            fi
        else
            echo -e "  ${YELLOW}⚠${NC} Rspamd installed but not running"
            ((warnings++))
        fi
    fi

    # 9. MySQL Socket and Thread Check
    if [[ "${HAS_MYSQL}" == true ]]; then
        echo -e "\n${BOLD}9. MySQL/MariaDB${NC}"
        if detect_mysql_socket; then
            echo -e "  ${GREEN}✓${NC} MySQL socket found: ${MYSQL_SOCKET}"

            # Test thread monitoring
            local mysqladmin_cmd="mysqladmin"
            if [[ -n "${MYSQL_SOCKET}" ]]; then
                mysqladmin_cmd="mysqladmin --socket=${MYSQL_SOCKET}"
            fi

            if ${mysqladmin_cmd} status >/dev/null 2>&1; then
                echo -e "  ${GREEN}✓${NC} Thread monitoring available"
            else
                echo -e "  ${YELLOW}⚠${NC} Thread monitoring may be limited"
            fi
        else
            echo -e "  ${YELLOW}⚠${NC} MySQL detected but no socket found - using TCP"
            ((warnings++))
        fi
    fi

    # 10. Service Status Summary
    echo -e "\n${BOLD}10. Monitored Services${NC}"
    local services=()
    [[ "${HAS_RSPAMD}" == true ]] && services+=("Rspamd")
    [[ "${HAS_MYSQL}" == true ]] && services+=("MySQL")
    [[ "${HAS_REDIS}" == true ]] && services+=("Redis")
    [[ "${HAS_EXIM}" == true ]] && services+=("Exim")
    [[ "${HAS_DOVECOT}" == true ]] && services+=("Dovecot")

    if [[ ${#services[@]} -gt 0 ]]; then
        echo -e "  ${GREEN}✓${NC} Monitoring: ${services[*]}"
    else
        echo -e "  ${YELLOW}○${NC} No additional services detected"
    fi

    # 11. Firewall Status
    echo -e "\n${BOLD}11. Firewall Configuration${NC}"
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
        systemctl restart snmpd || true
    else
        service snmpd restart || true
    fi
    sleep 5

    # Fix Rspamd permissions if needed
    if [[ "${HAS_RSPAMD}" == true ]]; then
        setup_rspamd_monitoring
    fi

    # Regenerate config
    generate_mrtg_config

    # Reinitialize with warmup
    initialize_mrtg

    # Fix cron if missing
    if ! crontab -l 2>/dev/null | grep -q "run-mrtg.sh"; then
        setup_cron
    fi

    # Fix logrotate if missing
    if [[ ! -f /etc/logrotate.d/mrtg ]]; then
        setup_logrotate
    fi

    # Fix permissions
    if [[ "${PANEL_TYPE}" == "directadmin" ]]; then
        if id diradmin >/dev/null 2>&1; then
            chown -R diradmin:diradmin "${WEB_MRTG_DIR}" 2>/dev/null || true
        fi
        chmod 755 "${WEB_MRTG_DIR}" 2>/dev/null || true
        find "${WEB_MRTG_DIR}" -type f -exec chmod 644 {} \; 2>/dev/null || true
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

    mkdir -p "${BACKUP_DIR}" 2>/dev/null || true

    # Backup configuration
    tar -czf "${backup_file}" \
        --exclude="${MRTG_LOG}/*" \
        --exclude="${MRTG_VAR}/*" \
        "${MRTG_CONF}" \
        "${MRTG_BIN}" \
        "${MRTG_SCRIPTS}" \
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
Rspamd: ${HAS_RSPAMD}
MySQL: ${HAS_MYSQL}
Redis: ${HAS_REDIS}
Exim: ${HAS_EXIM}
Dovecot: ${HAS_DOVECOT}
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
        crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | crontab - || true

        # Restore
        tar -xzf "${selected}" -C / 2>/dev/null || true

        # Restart services
        systemctl restart snmpd 2>/dev/null || service snmpd restart 2>/dev/null || true
        sleep 5

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
        echo -e "  - DirectAdmin plugin (if installed)"
        echo -e "  - Logrotate configuration"
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
    crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab - || true

    # Remove logrotate
    if [[ -f /etc/logrotate.d/mrtg ]]; then
        log "INFO" "Removing logrotate configuration..."
        rm -f /etc/logrotate.d/mrtg
    fi

    # Remove DirectAdmin plugin
    if [[ -d "/usr/local/directadmin/plugins/mrtg" ]]; then
        log "INFO" "Removing DirectAdmin plugin..."
        rm -rf "/usr/local/directadmin/plugins/mrtg"
    fi

    # Remove packages?
    if confirm_action "Remove MRTG and SNMP packages?"; then
        log "INFO" "Removing packages..."
        case "${OS_ID}" in
            ubuntu|debian)
                apt-get remove --purge -y mrtg snmpd snmp || true
                ;;
            centos|rhel|almalinux|rocky|fedora)
                yum remove -y mrtg net-snmp net-snmp-utils || true
                ;;
        esac
    fi

    # Remove data?
    if confirm_action "Remove all MRTG data?"; then
        log "INFO" "Removing files..."
        rm -rf "${MRTG_BASE}" "${MRTG_VAR}" "${WEB_MRTG_DIR}" || true

        # Restore SNMP config?
        local snmp_backup=$(ls -1 /etc/snmp/snmpd.conf.backup.* 2>/dev/null | head -1)
        if [[ -n "${snmp_backup}" ]] && confirm_action "Restore original SNMP config?"; then
            cp "${snmp_backup}" /etc/snmp/snmpd.conf || true
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
    # Use unquoted EOF to allow variable expansion
    cat << EOF
================================================================================
                 PROFESSIONAL MONITORING SUITE ${SCRIPT_VERSION}
================================================================================

This installer will:
  ✓ Detect your existing web server
  ✓ Configure secure SNMP monitoring
  ✓ Set up automatic data collection with lockfile protection
  ✓ Configure log rotation for maintenance-free operation
  ✓ Integrate with your control panel as a native plugin
  ✓ Monitor Rspamd email filter with timeout protection
  ✓ Monitor MySQL/MariaDB with thread analysis
  ✓ Monitor Redis, Exim, Dovecot (if detected)
  ✓ NEVER modify your web server

EOF

    check_root
    acquire_lock
    detect_os
    detect_control_panel
    detect_web_server
    detect_rspamd
    detect_mysql
    detect_redis
    detect_exim
    detect_dovecot

    echo -e "\n${BOLD}Detected Configuration:${NC}"
    echo -e "  OS: ${GREEN}${OS_NAME} ${OS_VERSION}${NC}"
    echo -e "  Web Server: ${GREEN}${WEB_SERVER}${NC}"
    echo -e "  Web User: ${GREEN}${WEB_USER}${NC}"
    echo -e "  Web Directory: ${GREEN}${WEB_MRTG_DIR}${NC}"

    if [[ "${PANEL_TYPE}" != "none" ]]; then
        echo -e "  Control Panel: ${GREEN}${PANEL_TYPE}${NC}"
    fi

    # Show detected services
    local services=()
    [[ "${HAS_RSPAMD}" == true ]] && services+=("Rspamd")
    [[ "${HAS_MYSQL}" == true ]] && services+=("MySQL")
    [[ "${HAS_REDIS}" == true ]] && services+=("Redis")
    [[ "${HAS_EXIM}" == true ]] && services+=("Exim")
    [[ "${HAS_DOVECOT}" == true ]] && services+=("Dovecot")

    if [[ ${#services[@]} -gt 0 ]]; then
        echo -e "  Services: ${GREEN}${services[*]}${NC}"
    fi

    echo -e "\n${BOLD}Configuration:${NC}"

    if [[ "${AUTO_MODE}" == true ]]; then
        # Auto mode - use defaults
        INTERVAL=${DEFAULT_INTERVAL}
        SNMP_COMMUNITY=${SNMP_COMMUNITY:-}  # will auto-generate later
        DEFAULT_EMAIL=${DEFAULT_EMAIL}
        log "INFO" "Auto mode enabled - using default values"
    else
        # Interactive mode - ask user
        read -p "Monitoring interval in minutes [${DEFAULT_INTERVAL}]: " interval
        INTERVAL=${interval:-${DEFAULT_INTERVAL}}

        read -p "SNMP Community String [auto-generate]: " snmp_input
        SNMP_COMMUNITY=${snmp_input}

        read -p "Notification email [${DEFAULT_EMAIL}]: " email_input
        DEFAULT_EMAIL=${email_input:-${DEFAULT_EMAIL}}
    fi

    echo -e "\n${YELLOW}Summary:${NC}"
    echo -e "  Interval: ${INTERVAL} minutes"
    echo -e "  SNMP: ${SNMP_COMMUNITY:-"<auto-generated>"}"
    echo -e "  Email: ${DEFAULT_EMAIL}"
    echo -e "  Services: ${#services[@]} detected"
    echo -e "  Log Rotation: Weekly (auto-configured)"
    echo -e "  CPU Priority: Low (nice/ionice)"
    echo ""

    if [[ "${AUTO_MODE}" != true ]] && ! confirm_action "Proceed with installation?"; then
        log "INFO" "Installation cancelled"
        return 0
    fi

    log "INFO" "Starting installation..."

    install_dependencies
    create_directories
    configure_snmp
    configure_firewall

    if [[ "${HAS_RSPAMD}" == true ]]; then
        setup_rspamd_monitoring
    fi

    generate_mrtg_config
    setup_web_access
    configure_panel_integration
    setup_cron
    setup_logrotate
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
HAS_RSPAMD="${HAS_RSPAMD}"
HAS_MYSQL="${HAS_MYSQL}"
HAS_REDIS="${HAS_REDIS}"
HAS_EXIM="${HAS_EXIM}"
HAS_DOVECOT="${HAS_DOVECOT}"
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
    echo -e "Logs: ${CYAN}${MRTG_LOG}/mrtg.log${NC}"
    echo -e "Log Rotation: ${CYAN}/etc/logrotate.d/mrtg${NC}"
    echo -e "CPU Priority: ${CYAN}Low (nice/ionice)${NC}"

    if [[ ${#services[@]} -gt 0 ]]; then
        echo -e "Monitored Services: ${CYAN}${services[*]}${NC}"
    fi

    echo ""
    verify_system_health
}

# =============================================================================
# INTERACTIVE MENU
# =============================================================================

show_menu() {
    clear
    cat << EOF
================================================================================
                    MRTG PROFESSIONAL MONITORING SUITE
================================================================================
                         Enterprise Edition ${SCRIPT_VERSION}
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
    echo -e "  ${GREEN}12)${NC} Auto Install (Unattended)"
    echo -e "  ${GREEN}0)${NC} Exit\n"

    read -p "Enter choice [0-12]: " choice

    case ${choice} in
        1) installation_wizard ;;
        2) uninstall_mrtg ;;
        3)
            detect_web_server
            detect_rspamd
            detect_mysql
            detect_redis
            detect_exim
            detect_dovecot
            verify_system_health
            ;;
        4)
            detect_web_server
            detect_rspamd
            detect_mysql
            detect_redis
            detect_exim
            detect_dovecot
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
                crontab -l 2>/dev/null | grep -v "run-mrtg.sh" | grep -v "mrtg" | crontab - || true
                log "SUCCESS" "Cron removed"
            fi
            ;;
        10)
            if [[ -f "${MRTG_LOG}/mrtg.log" ]]; then
                tail -50 "${MRTG_LOG}/mrtg.log" 2>/dev/null || true
            else
                log "ERROR" "Log not found"
            fi
            ;;
        11)
            DRY_RUN=true
            installation_wizard
            DRY_RUN=false
            ;;
        12)
            AUTO_MODE=true
            installation_wizard
            AUTO_MODE=false
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
    # Menu loops in main()
}

# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

print_help() {
    cat << EOF
${BOLD}NAME${NC}
    ${SCRIPT_NAME} - MRTG Professional Monitoring Suite ${SCRIPT_VERSION}

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
    --auto, -a        Unattended installation (uses defaults)
    --dry-run         Test without changes
    --force           Skip confirmations
    --version, -v     Show version
    --help, -h        Show this help

${BOLD}EXAMPLES${NC}
    ${SCRIPT_NAME} --install      # Install MRTG with all service monitoring
    ${SCRIPT_NAME} --auto         # Unattended installation with defaults
    ${SCRIPT_NAME} --status       # Check system health
    ${SCRIPT_NAME} --repair       # Fix common issues
    ${SCRIPT_NAME} --update       # Update script from GitHub
    ${SCRIPT_NAME} --uninstall    # Remove MRTG completely

${BOLD}FILES${NC}
    ${MRTG_BASE}         Main installation directory
    ${MRTG_CONF}         Configuration files
    ${MRTG_LOG}          Log files
    ${MRTG_SCRIPTS}      Helper scripts (Rspamd, etc)
    ${BACKUP_DIR}        Backup storage

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
    touch "${LOG_FILE}" 2>/dev/null || true
    chmod 644 "${LOG_FILE}" 2>/dev/null || true

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
                detect_rspamd
                detect_mysql
                detect_redis
                detect_exim
                detect_dovecot
                verify_system_health
                ;;
            --repair|-r)
                check_root
                detect_web_server
                detect_rspamd
                detect_mysql
                detect_redis
                detect_exim
                detect_dovecot
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
            --auto|-a)
                check_root
                AUTO_MODE=true
                installation_wizard
                AUTO_MODE=false
                ;;
            --dry-run)
                check_root
                DRY_RUN=true
                installation_wizard
                DRY_RUN=false
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
        while true; do
            show_menu
        done
    fi
}

# Trap
trap 'rm -f "${LOCK_FILE}"' EXIT
trap 'error_handler $? $LINENO' ERR

# Run main function
main "$@"
