# Ransomware Security Configuration Scanner

### Python-Based Automated Security Assessment for Linux and Windows

## Overview

This project was developed as part of my Final Year Project (FYP) at Asia Pacific University of Technology & Innovation (APU).

The aim of this project is to develop an automated security configuration assessment system that helps identify ransomware-related security misconfigurations across Linux and Windows environments.

Instead of relying entirely on manual security checks, the system uses Python-based scanning modules to remotely assess security configurations, evaluate potential risks, and provide remediation recommendations.

The project focuses on security assessment, automation, and defensive security practices.

## Key Features

**1. Linux Security Configuration Scanning**
- Remote security assessment using SSH and Paramiko
- Firewall configuration checks
- SSH root login and password authentication checks
- Security update assessment
- Fail2Ban configuration checks

**2. Windows Security Configuration Scanning**
- Remote assessment using WinRM
- Windows Firewall configuration checks
- Remote Desktop Protocol (RDP) assessment
- Microsoft Defender status checks
- Password policy assessment
- Administrator and Guest account checks

**3. Risk Assessment**
- Classification of security check results
- Identification of potential misconfigurations
- Risk scoring and severity categorisation
- Remediation recommendations

**4. Web-Based Management Dashboard**
- Flask-based interface
- Target machine management
- Manual and scheduled security assessments
- Scan history and result visualisation

**5. Automated Reporting**
- PDF security assessment reports
- Security findings and risk summaries
- Recommended remediation actions

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core scanning and automation |
| Flask | Web-based dashboard |
| Paramiko | SSH communication with Linux |
| pywinrm | Remote Windows management |
| ReportLab | PDF report generation |
| HTML / CSS | Dashboard interface |

## System Workflow

1. Administrator registers a target machine.
2. The system identifies the target operating system.
3. The relevant scanning module establishes a remote connection.
4. Security configuration checks are performed.
5. Findings are evaluated by the risk scoring module.
6. Results are stored and displayed on the dashboard.
7. A security assessment report can be generated.

## Security Considerations

This project is intended for educational purposes and authorised security assessments only.

- Assess only systems that you own or have permission to test.
- Do not publish credentials, private keys, or sensitive target information.
- Use isolated laboratory environments when demonstrating security misconfigurations.
- Treat scan results as configuration findings rather than proof of exploitation.

## Project Background

**Project Type:** University Final Year Project  
**Field:** Cybersecurity / Security Automation  
**Institution:** Asia Pacific University of Technology & Innovation (APU)

## Future Improvements

- Expand security configuration checks.
- Introduce additional compliance benchmark mappings.
- Improve risk scoring and prioritisation.
- Support more operating systems and environments.
- Enhance automated security reporting.

## Disclaimer

This tool is designed to support security configuration assessment and does not guarantee detection or prevention of all ransomware threats.