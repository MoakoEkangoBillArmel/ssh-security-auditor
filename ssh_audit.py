#!/usr/bin/env python3
"""
SSH Security Auditor & Hardening Tool

A professional, zero-dependency Python script to audit sshd_config files
and generate hardened configurations based on cybersecurity best practices.
"""

import argparse
import re
import os
import sys
from datetime import datetime
from typing import List, Dict, Tuple, Any

# ANSI escape codes for terminal colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Recommended SSH configurations (Hardening Guidelines)
RECOMMENDED_CONFIG: Dict[str, str] = {
    "Protocol": "2",
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "MaxAuthTries": "3",
    "StrictModes": "yes",
    "IgnoreRhosts": "yes",
    "HostbasedAuthentication": "no",
    "PermitUserEnvironment": "no",
    "ClientAliveInterval": "300",
    "ClientAliveCountMax": "0",
    "UsePAM": "yes"
}

def print_info(msg: str) -> None:
    """Print an informational message."""
    print(f"{Colors.OKCYAN}[*]{Colors.ENDC} {msg}")

def print_success(msg: str) -> None:
    """Print a success message."""
    print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {msg}")

def print_warning(msg: str) -> None:
    """Print a warning message."""
    print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")

def print_error(msg: str) -> None:
    """Print an error message."""
    print(f"{Colors.FAIL}[-]{Colors.ENDC} {msg}")

def parse_config(filepath: str) -> Tuple[List[str], Dict[str, str]]:
    """Parses the SSH config file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print_error(f"Failed to read file {filepath}: {e}")
        sys.exit(1)
        
    config_dict = {}
    for line in lines:
        line_stripped = line.strip()
        # Ignore comments and empty lines
        if not line_stripped or line_stripped.startswith('#'):
            continue
            
        # Match Key Value pair (can be separated by space or =)
        match = re.match(r'^([a-zA-Z0-9]+)\s+(.+)$', line_stripped)
        if match:
            key, value = match.groups()
            config_dict[key] = value
            
    return lines, config_dict

def audit_config(current_config: Dict[str, str]) -> List[Dict[str, Any]]:
    """Compares current settings with recommended settings."""
    issues = []
    for key, recommended_value in RECOMMENDED_CONFIG.items():
        if key in current_config:
            current_value = current_config[key]
            if current_value != recommended_value:
                issues.append({
                    "key": key,
                    "current": current_value,
                    "recommended": recommended_value,
                    "status": "Vulnerable/Suboptimal"
                })
        else:
            issues.append({
                "key": key,
                "current": "Not explicitly set",
                "recommended": recommended_value,
                "status": "Missing (Relies on default)"
            })
    return issues

def generate_hardened_config(lines: List[str], issues: List[Dict[str, Any]], output_filepath: str) -> None:
    """Generates a hardened config file."""
    hardened_lines = []
    keys_to_update = {issue['key']: issue['recommended'] for issue in issues}
    keys_updated = set()
    
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            hardened_lines.append(line)
            continue
            
        match = re.match(r'^([a-zA-Z0-9]+)\s+(.+)$', line_stripped)
        if match:
            key, value = match.groups()
            if key in keys_to_update:
                hardened_lines.append(f"{key} {keys_to_update[key]}\n")
                keys_updated.add(key)
            else:
                hardened_lines.append(line)
        else:
            hardened_lines.append(line)
            
    # Add any missing recommended configurations at the end
    missing_keys = set(keys_to_update.keys()) - keys_updated
    if missing_keys:
        hardened_lines.append("\n# --- Hardened Configurations Added by Auditor ---\n")
        for key in missing_keys:
            hardened_lines.append(f"{key} {keys_to_update[key]}\n")
            
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.writelines(hardened_lines)
        print_success(f"Hardened config saved to: {Colors.BOLD}{output_filepath}{Colors.ENDC}")
    except Exception as e:
        print_error(f"Failed to write to {output_filepath}: {e}")

def generate_markdown_report(issues: List[Dict[str, Any]], report_filepath: str) -> None:
    """Generates a Markdown report of the audit."""
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        with open(report_filepath, 'w', encoding='utf-8') as f:
            f.write("# SSH Security Audit Report\n\n")
            f.write(f"**Date:** {date_str}\n\n")
            
            if not issues:
                f.write("✅ **Congratulations!** Your SSH configuration is secure and aligns with all recommended hardening guidelines.\n")
                return
                
            f.write("## ⚠️ Vulnerabilities and Misconfigurations Detected\n\n")
            f.write("| Directive | Current Value | Recommended Value | Status |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            
            for issue in issues:
                icon = "🔴" if issue["status"] == "Vulnerable/Suboptimal" else "🟠"
                f.write(f"| {issue['key']} | `{issue['current']}` | `{issue['recommended']}` | {icon} {issue['status']} |\n")
                
            f.write("\n## Recommendations\n")
            f.write("A hardened configuration file (`sshd_config_hardened.conf`) has been generated. ")
            f.write("Please review the changes and deploy them using caution. Always ensure you have a fallback method to access your server before restarting the SSH service.\n")
            
        print_success(f"Audit report saved to: {Colors.BOLD}{report_filepath}{Colors.ENDC}")
    except Exception as e:
        print_error(f"Failed to write to {report_filepath}: {e}")

def main():
    parser = argparse.ArgumentParser(description="SSH Security Auditor & Hardening Tool")
    parser.add_argument("config_file", help="Path to the sshd_config file to audit")
    parser.add_argument("-o", "--output", default="sshd_config_hardened.conf", help="Output path for the hardened config")
    parser.add_argument("-r", "--report", default="audit_report.md", help="Output path for the Markdown report")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.config_file):
        print_error(f"File '{args.config_file}' not found.")
        sys.exit(1)
        
    print_info(f"Starting audit for: {Colors.BOLD}{args.config_file}{Colors.ENDC}...")
    lines, current_config = parse_config(args.config_file)
    
    issues = audit_config(current_config)
    
    if issues:
        print_warning(f"Found {len(issues)} security issues/misconfigurations.")
    else:
        print_success("No security issues found.")
        
    generate_hardened_config(lines, issues, args.output)
    generate_markdown_report(issues, args.report)
    print_info("Audit complete.")

if __name__ == "__main__":
    main()
