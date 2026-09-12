# SSH Security Auditer & Hardening Tool 🛡️

A lightweight, professional, and automated Python tool designed to audit SSH server configurations (`sshd_config`) and generate hardened, secure configurations based on cybersecurity best practices.

## 📌 Features

- **Automated Parsing:** Reads and parses `sshd_config` files accurately.
- **Security Auditing:** Checks configurations against a baseline of strict security guidelines (e.g., disabling root login, enforcing Protocol 2, mitigating brute force via `MaxAuthTries`).
- **Hardening Generation:** Automatically generates a new `sshd_config_hardened.conf` file, patching identified vulnerabilities while preserving non-relevant existing configurations and comments.
- **Markdown Reporting:** Produces a clean, readable `audit_report.md` detailing the vulnerabilities found and the recommendations applied.

## 🚀 Quick Start

### Prerequisites
- Python 3.6+
- No external dependencies required (uses built-in libraries like `re`, `argparse`, and `os`).

### Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ssh-security-auditor.git
   cd ssh-security-auditor
   ```

2. **Run the auditor against a config file:**
   ```bash
   # You can test with the provided vulnerable mock file
   python ssh_audit.py sshd_config_vulnerable.txt
   ```

3. **Check the outputs:**
   - Review the generated `audit_report.md` for a summary of issues.
   - Inspect `sshd_config_hardened.conf` for the applied security fixes.

### Command-line Arguments

```bash
usage: ssh_audit.py [-h] [-o OUTPUT] [-r REPORT] config_file

SSH Security Auditer & Hardening Tool

positional arguments:
  config_file           Path to the sshd_config file to audit

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output path for the hardened config (default: sshd_config_hardened.conf)
  -r REPORT, --report REPORT
                        Output path for the Markdown report (default: audit_report.md)
```

## 🔐 Security Guidelines Implemented

This tool enforces the following best practices:
- `Protocol 2` (Prevents downgrade attacks)
- `PermitRootLogin no` (Mitigates direct root brute-forcing)
- `PasswordAuthentication no` (Enforces key-based authentication)
- `PermitEmptyPasswords no` (Ensures no account can log in without a password/key)
- `X11Forwarding no` (Reduces attack surface)
- `MaxAuthTries 3` (Slows down brute-force attacks)
- `StrictModes yes` (Ensures correct permissions on keys)
- `IgnoreRhosts yes` (Disables legacy, insecure `.rhosts` auth)
- `HostbasedAuthentication no` (Prevents pivoting from compromised hosts)
- `PermitUserEnvironment no` (Prevents environment variable manipulation)
- `ClientAliveInterval 300` & `ClientAliveCountMax 0` (Prevents idle sessions from lingering indefinitely)

## ⚠️ Disclaimer

Always review the generated `sshd_config_hardened.conf` before deploying it to a production server. A misconfigured SSH daemon can lock you out of your system. Always ensure you have a backup or alternate access method (e.g., console access) before restarting the `sshd` service.

## 📄 License

This project is open-source and available under the MIT License.
