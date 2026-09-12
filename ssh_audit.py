import argparse
import re
import os
from datetime import datetime

# Define recommended SSH configurations (Hardening Guidelines)
RECOMMENDED_CONFIG = {
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

def parse_config(filepath):
    """Parses the SSH config file and returns a list of lines and a dictionary of current settings."""
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
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

def audit_config(current_config):
    """Compares current settings with recommended settings."""
    issues = []
    for key, recommended_value in RECOMMENDED_CONFIG.items():
        if key in current_config:
            current_value = current_config[key]
            # Special case for PermitRootLogin as 'prohibit-password' is also acceptable for some policies, 
            # but we enforce 'no' as a stricter rule here.
            # Special case for Protocol which could be '2,1'
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

def generate_hardened_config(lines, issues, output_filepath):
    """Generates a hardened config file by updating vulnerable lines and adding missing ones."""
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
            
    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.writelines(hardened_lines)
    print(f"[+] Hardened config saved to: {output_filepath}")

def generate_markdown_report(issues, report_filepath):
    """Generates a Markdown report of the audit."""
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
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
        
    print(f"[+] Audit report saved to: {report_filepath}")

def main():
    parser = argparse.ArgumentParser(description="SSH Security Auditer & Hardening Tool")
    parser.add_argument("config_file", help="Path to the sshd_config file to audit")
    parser.add_argument("-o", "--output", default="sshd_config_hardened.conf", help="Output path for the hardened config")
    parser.add_argument("-r", "--report", default="audit_report.md", help="Output path for the Markdown report")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.config_file):
        print(f"[-] Error: File '{args.config_file}' not found.")
        return
        
    print(f"[*] Starting audit for: {args.config_file}...")
    lines, current_config = parse_config(args.config_file)
    
    issues = audit_config(current_config)
    
    if issues:
        print(f"[*] Found {len(issues)} security issues/misconfigurations.")
    else:
        print("[*] No security issues found.")
        
    generate_hardened_config(lines, issues, args.output)
    generate_markdown_report(issues, args.report)
    print("[*] Audit complete.")

if __name__ == "__main__":
    main()
