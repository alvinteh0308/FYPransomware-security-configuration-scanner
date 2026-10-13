import getpass
import html
import os
import re
from datetime import datetime
from typing import Dict, List, Optional

import paramiko

try:
    import winrm
except ImportError:
    winrm = None


# =========================================================
# COMMON REPORTING
# =========================================================

def make_result(check, status, risk, details, remediation, target_ip, os_type):
    return {
        "target_ip": target_ip,
        "os": os_type,
        "check": check,
        "status": status,
        "risk": risk,
        "details": details,
        "remediation": remediation
    }


def print_banner():
    print("=" * 75)
    print(" CENTRALIZED RANSOMWARE MISCONFIGURATION SCANNER")
    print("=" * 75)
    print("This tool scans Linux and Windows targets for ransomware-related")
    print("security misconfigurations such as firewall, remote access,")
    print("password policy, patch status, and privileged accounts.")
    print("=" * 75)


def print_result(item: Dict):
    print("\n" + "=" * 75)
    print(f"TARGET      : {item['target_ip']} ({item['os']})")
    print(f"CHECK       : {item['check']}")
    print(f"STATUS      : {item['status']}")
    print(f"RISK        : {item['risk']}")
    print(f"DETAILS     : {item['details']}")
    print(f"REMEDIATION : {item['remediation']}")


def print_summary(results: List[Dict]):
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    info = sum(1 for r in results if r["status"] == "INFO")

    high = sum(1 for r in results if r["risk"] == "HIGH")
    medium = sum(1 for r in results if r["risk"] == "MEDIUM")
    low = sum(1 for r in results if r["risk"] == "LOW")

    print("\n" + "#" * 75)
    print("SCAN SUMMARY")
    print("#" * 75)
    print(f"Total checks : {len(results)}")
    print(f"PASS         : {passed}")
    print(f"FAIL         : {failed}")
    print(f"INFO         : {info}")
    print(f"HIGH risk    : {high}")
    print(f"MEDIUM risk  : {medium}")
    print(f"LOW risk     : {low}")

def safe_filename(text: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', text)

def generate_html_report(results):
    if not results:
        print("[!] No results to generate report.")
        return

    os_type = results[0]["os"]
    target_ip = results[0]["target_ip"]

    folder_name = "Linux" if os_type.lower() == "linux" else "Windows"
    os.makedirs(folder_name, exist_ok=True)

    safe_ip = safe_filename(target_ip)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = os.path.join(
        folder_name,
        f"{folder_name}_report_{safe_ip}_{timestamp}.html"
    )

    rows = ""
    for r in results:
        rows += f"""
        <tr class="{r['status']}">
            <td>{r['target_ip']}</td>
            <td>{r['os']}</td>
            <td>{r['check']}</td>
            <td>{r['status']}</td>
            <td>{r['risk']}</td>
            <td><pre>{r['details']}</pre></td>
            <td>{r['remediation']}</td>
        </tr>
        """

    html_report = f"""
    <html>
    <head>
        <title>{folder_name} Security Scan Report</title>
        <style>
            body {{ font-family: Arial; background:#f4f4f4; margin:30px; }}
            h1 {{ text-align:center; }}
            table {{ border-collapse: collapse; width:100%; background:white; }}
            th, td {{ border:1px solid #ccc; padding:10px; text-align:left; vertical-align:top; }}
            th {{ background:#333; color:white; }}
            pre {{ white-space:pre-wrap; margin:0; }}
            .PASS {{ background:#c8e6c9; }}
            .FAIL {{ background:#ffcdd2; }}
            .INFO {{ background:#fff9c4; }}
        </style>
    </head>
    <body>
        <h1>{folder_name} Security Scan Report</h1>
        <h3>Target IP: {target_ip}</h3>

        <table>
            <tr>
                <th>Target IP</th>
                <th>OS</th>
                <th>Check</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Details</th>
                <th>Remediation</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_report)

    print(f"\n[+] HTML report generated: {filename}")

# =========================================================
# LINUX SSH FUNCTIONS
# =========================================================

def connect_ssh(host: str, username: str, password: str):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=username, password=password, timeout=10)
    return client


def run_ssh_command(client, command: str) -> str:
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode("utf-8", errors="ignore").strip()
    error = stderr.read().decode("utf-8", errors="ignore").strip()

    if output and error:
        return output + "\n" + error
    return output or error


def run_sudo_command(client, command: str, sudo_password: str) -> str:
    sudo_cmd = f"echo '{sudo_password}' | sudo -S {command}"
    stdin, stdout, stderr = client.exec_command(sudo_cmd)

    output = stdout.read().decode("utf-8", errors="ignore").strip()
    error = stderr.read().decode("utf-8", errors="ignore").strip()

    cleaned_error = "\n".join(
        line for line in error.splitlines()
        if "password for" not in line.lower()
    ).strip()

    if output and cleaned_error:
        return output + "\n" + cleaned_error
    return output or cleaned_error


def linux_check_firewall(client, password, ip):
    output = run_sudo_command(client, "ufw status", password)
    lower = output.lower()

    if "inactive" in lower:
        return make_result("Firewall Status", "FAIL", "HIGH", output,
                           "Enable UFW and allow required services only.", ip, "Linux")
    if "status: active" in lower:
        return make_result("Firewall Status", "PASS", "LOW", output,
                           "Firewall is enabled. Review rules regularly.", ip, "Linux")

    return make_result("Firewall Status", "INFO", "MEDIUM", output or "No output",
                       "Manually verify firewall configuration.", ip, "Linux")


def linux_check_ssh_root_login(client, ip):
    cmd = r"grep -i '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null"
    output = run_ssh_command(client, cmd)
    lower = output.lower()

    if "permitrootlogin yes" in lower:
        return make_result("SSH Root Login", "FAIL", "HIGH", output,
                           "Set PermitRootLogin no and restart SSH service.", ip, "Linux")
    if "permitrootlogin no" in lower:
        return make_result("SSH Root Login", "PASS", "LOW", output,
                           "Root SSH login is disabled.", ip, "Linux")

    return make_result("SSH Root Login", "INFO", "MEDIUM",
                       output or "PermitRootLogin not explicitly set.",
                       "Explicitly set PermitRootLogin no.", ip, "Linux")


def linux_check_password_auth(client, ip):
    cmd = r"grep -i '^PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null"
    output = run_ssh_command(client, cmd)
    lower = output.lower()

    if "passwordauthentication yes" in lower:
        return make_result("SSH Password Authentication", "FAIL", "MEDIUM", output,
                           "Disable password authentication if SSH key login is available.", ip, "Linux")
    if "passwordauthentication no" in lower:
        return make_result("SSH Password Authentication", "PASS", "LOW", output,
                           "Password authentication is disabled.", ip, "Linux")

    return make_result("SSH Password Authentication", "INFO", "MEDIUM",
                       output or "PasswordAuthentication not explicitly set.",
                       "Explicitly define PasswordAuthentication in SSH config.", ip, "Linux")


def linux_check_updates(client, password, ip):
    output = run_sudo_command(client, "apt list --upgradable 2>/dev/null | tail -n +2", password)
    lines = [line for line in output.splitlines() if line.strip()]
    count = len(lines)

    if count == 0:
        return make_result("Pending Updates", "PASS", "LOW", "No pending updates found.",
                           "System appears up to date.", ip, "Linux")

    risk = "HIGH" if count >= 10 else "MEDIUM"
    return make_result("Pending Updates", "FAIL", risk,
                       f"{count} upgradable package(s).\n{output}",
                       "Apply pending updates promptly.", ip, "Linux")


def linux_check_fail2ban(client, ip):
    output = run_ssh_command(client, "systemctl is-active fail2ban")

    if "active" in output.lower():
        return make_result("Fail2Ban Presence", "PASS", "LOW", output,
                           "Fail2Ban is running.", ip, "Linux")

    return make_result("Fail2Ban Presence", "INFO", "MEDIUM", output or "Not active",
                       "Install and enable Fail2Ban to reduce brute-force risk.", ip, "Linux")


def scan_linux(ip, username, password) -> List[Dict]:
    print(f"\n[*] Connecting to Linux target {ip}...")
    client = connect_ssh(ip, username, password)
    print("[+] Connected successfully.")

    results = [
        linux_check_firewall(client, password, ip),
        linux_check_ssh_root_login(client, ip),
        linux_check_password_auth(client, ip),
        linux_check_updates(client, password, ip),
        linux_check_fail2ban(client, ip)
    ]

    client.close()
    return results


# =========================================================
# WINDOWS WINRM FUNCTIONS
# =========================================================

def run_win_cmd(session, command: str) -> str:
    result = session.run_cmd(command)
    output = result.std_out.decode(errors="ignore").strip()
    error = result.std_err.decode(errors="ignore").strip()
    return output or error


def windows_check_firewall(session, ip):
    output = run_win_cmd(session, "netsh advfirewall show allprofiles")

    if "State                                 ON" in output:
        return make_result("Windows Firewall", "PASS", "LOW", "Firewall is enabled.",
                           "Review firewall rules regularly.", ip, "Windows")

    return make_result("Windows Firewall", "FAIL", "HIGH", "Firewall may be disabled.",
                       "Enable Windows Firewall for all profiles.", ip, "Windows")


def windows_check_rdp(session, ip):
    output = run_win_cmd(
        session,
        r'reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections'
    )

    if "0x1" in output:
        return make_result("RDP Status", "PASS", "LOW", "RDP is disabled.",
                           "RDP is disabled.", ip, "Windows")

    return make_result("RDP Status", "FAIL", "HIGH", "RDP is enabled.",
                       "Disable RDP if it is not required.", ip, "Windows")


def windows_check_password_policy(session, ip):
    output = run_win_cmd(session, "net accounts")

    if "Minimum password length:                              0" in output:
        return make_result("Password Policy", "FAIL", "HIGH", output,
                           "Set minimum password length and stronger password policy.", ip, "Windows")

    return make_result("Password Policy", "PASS", "LOW", output,
                       "Password policy appears configured.", ip, "Windows")


def windows_check_defender(session, ip):
    output = run_win_cmd(
        session,
        'powershell -Command "Get-MpComputerStatus | Select-Object AntivirusEnabled | Out-String"'
    )

    if "True" in output:
        return make_result("Windows Defender", "PASS", "LOW", "Defender is enabled.",
                           "Keep Microsoft Defender enabled and updated.", ip, "Windows")

    return make_result("Windows Defender", "FAIL", "HIGH", "Defender is disabled.",
                       "Enable Microsoft Defender Antivirus.", ip, "Windows")


def windows_check_admin_account(session, ip):
    output = run_win_cmd(session, "net user Administrator")

    if "Account active               Yes" in output:
        return make_result("Administrator Account", "FAIL", "HIGH",
                           "Default Administrator account is enabled.",
                           "Disable or rename the default Administrator account.", ip, "Windows")

    return make_result("Administrator Account", "PASS", "LOW",
                       "Default Administrator account is disabled.",
                       "Administrator account is disabled.", ip, "Windows")


def windows_check_guest_account(session, ip):
    output = run_win_cmd(session, "net user Guest")

    if "Account active               Yes" in output:
        return make_result("Guest Account", "FAIL", "HIGH", "Guest account is enabled.",
                           "Disable the Guest account.", ip, "Windows")

    return make_result("Guest Account", "PASS", "LOW", "Guest account is disabled.",
                       "Guest account is disabled.", ip, "Windows")


def scan_windows(ip, username, password) -> List[Dict]:
    if winrm is None:
        raise ImportError("pywinrm is not installed. Install it using: pip install pywinrm")

    print(f"\n[*] Connecting to Windows target {ip} using WinRM...")
    session = winrm.Session(
        f"http://{ip}:5985/wsman",
        auth=(username, password)
    )
    print("[+] Connected successfully.")

    return [
        windows_check_firewall(session, ip),
        windows_check_rdp(session, ip),
        windows_check_password_policy(session, ip),
        windows_check_defender(session, ip),
        windows_check_admin_account(session, ip),
        windows_check_guest_account(session, ip)
    ]


# =========================================================
# USER INTERACTION
# =========================================================

def get_target_input():
    print("\nSelect target operating system:")
    print("1. Linux")
    print("2. Windows")

    choice = input("Enter choice: ").strip()

    if choice == "1":
        os_type = "linux"
    elif choice == "2":
        os_type = "windows"
    else:
        print("[!] Invalid OS selection.")
        return None

    ip = input("Enter target IP address: ").strip()
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ")

    return os_type, ip, username, password


def run_single_scan():
    target = get_target_input()
    if not target:
        return []

    os_type, ip, username, password = target

    if os_type == "linux":
        return scan_linux(ip, username, password)
    else:
        return scan_windows(ip, username, password)


def run_multiple_scan():
    all_results = []

    while True:
        results = run_single_scan()
        all_results.extend(results)

        again = input("\nAdd another target? (y/n): ").strip().lower()
        if again != "y":
            break

    return all_results


def main():
    print_banner()

    all_results = []

    while True:
        print("\nMAIN MENU")
        print("1. Scan one target")
        print("2. Scan multiple targets")
        print("3. Exit")

        choice = input("Select option: ").strip()

        try:
            if choice == "1":
                all_results = run_single_scan()
            elif choice == "2":
                all_results = run_multiple_scan()
            elif choice == "3":
                print("Exiting scanner.")
                break
            else:
                print("[!] Invalid option.")
                continue

            if all_results:
                for item in all_results:
                    print_result(item)

                print_summary(all_results)
                generate_html_report(all_results)

        except Exception as e:
            print(f"[!] Error: {e}")

        again = input("\nReturn to main menu? (y/n): ").strip().lower()
        if again != "y":
            break


if __name__ == "__main__":
    main()
