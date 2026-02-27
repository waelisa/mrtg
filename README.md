# 📊 MRTG Professional Monitoring Suite - Enterprise Edition

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.2.1-blue.svg)](#)
[![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25.svg)](https://www.gnu.org/software/bash/)

The definitive, zero-assumption MRTG installer for production hosting environments.

Most MRTG installers assume a "vanilla" OS. This suite is different. It was built specifically for DirectAdmin, cPanel, and Plesk environments where web servers, firewalls, and service paths are often customized.

🚀 Key Features

    🛡️ Production Hardened: Includes a lock-file system to prevent race conditions and data corruption.

    🔍 Auto-Detection: Dynamically detects Apache, Nginx, LiteSpeed, and Caddy.

    📧 Mail Stack Monitoring: Deep integration for Rspamd (scanned vs. rejected), Exim, and Dovecot.

    🗄️ Database Insights: Monitors MySQL/MariaDB connections and running threads.

    ⚡ Cache Monitoring: Native support for Redis memory and command throughput.

    🔥 Firewall Aware: Automatically patches CSF, Firewalld, UFW, or iptables to allow SNMP traffic.

    🔌 Hosting Panel Ready: Native plugin support for DirectAdmin "Admin Level" visibility.

🛠️ Installation

Quick Start (Interactive)

Run the following command as root to start the guided installation wizard:
```bash
wget https://raw.githubusercontent.com/waelisa/mrtg/main/install-mrtg.sh
chmod +x install-mrtg.sh
./install-mrtg.sh
```
Automated / Headless

For bulk deployment via Ansible or SSH loops:
```bash
./install-mrtg.sh --auto
```

📈 Monitored Metrics

Category	Description

System	CPU Load, Physical Memory, Swap Usage, Disk I/O

Network	Interface Throughput (In/Out), Error packets

Web	Web Server Status, Request Latency

Email	Rspamd Spam Filtering, Exim Queue, Dovecot Logins

Database	MySQL Threads Connected, Running Queries

⚙️ Advanced Usage

The script includes a full suite of maintenance tools accessible via flags:

    --status: Run a 12-point system health diagnostic.

    --backup: Create a timestamped backup of your MRTG configurations.

    --repair: Fix broken permissions, missing cron jobs, or stale lock files.

    --update: Check for and apply the latest version of the Monitoring Suite.

🤝 Contributing

    Fork the Project

    Create your Feature Branch (git checkout -b feature/AmazingFeature)

    Commit your Changes (git commit -m 'Add some AmazingFeature')

    Push to the Branch (git push origin feature/AmazingFeature)

    Open a Pull Request

📄 License

Distributed under the MIT License. See LICENSE for more information.

## ☕ Support the Project

[![Donate with PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.me/WaelIsa)
