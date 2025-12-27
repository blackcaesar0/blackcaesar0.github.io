+++
date = '2025-02-06T06:19:49+01:00'
draft = false
title = 'Intelligence'
+++
---
# Intelligence CTF Write-Up

## Executive Summary
Intelligence contracted **blackcaesar0** to perform a network penetration test on its internally facing network. The objective was to identify security weaknesses, determine their impact, and provide remediation recommendations.

## Approach
The test was conducted using a **black-box approach** from **January 16, 2025, 10:14 PM, to January 21, 2025, 4:16 AM**, without credentials or prior knowledge of the internal environment. The goal was to uncover unknown vulnerabilities while maintaining a non-evasive testing approach.

## Scope
- **Network IP:** `10.129.95.154`
- **Domain:** `intelligence.htb`

## Assessment Overview and Key Findings
The penetration tester successfully compromised the `intelligence.htb` domain through:
- Web application vulnerabilities
- Credential harvesting
- SMB enumeration
- Active Directory misconfigurations
- Kerberos delegation abuse

## Key Findings
### Web Application Vulnerability
- Predictable naming conventions exposed sensitive data, leading to the discovery of a **default password**.

### Password Spray Attack
- The default password led to the compromise of the **Tiffany.molina** account via SMB access.

### Sensitive File Discovery
- SMB enumeration revealed a **PowerShell script** (privileged operation of `Ted.graves`).
- Located `user.txt` in Tiffany's home directory.

### DNS Misconfiguration
- Used the PowerShell script to create a **DNS entry** and capture **Ted.graves' NTLMv2 hash**, which was cracked offline.

### Active Directory Misconfigurations
- **ReadGMSAPassword abuse** on `svc_int$`, allowing retrieval of the **gMSA NTLM hash**.
- The `svc_int$` account had **AllowedToDelegate** enabled, permitting impersonation of **domain administrator**.

### Privilege Escalation via Kerberos Delegation
- Using the **gMSA hash** and **AllowedToDelegate**, the tester **forged a Kerberos service ticket** with `impacket-getST`, gaining **administrative access** to the domain controller.

## Recommendations
### Web Application Security
- Implement **input validation** and avoid predictable naming conventions.
- **Remove default credentials** from publicly accessible systems.
- **Conduct regular security audits** to identify vulnerabilities.

### Credential Security
- Enforce **strong password policies** and **regular rotations**.
- Monitor and limit **login attempts** to detect password spray attacks.
- Enable **Multi-Factor Authentication (MFA)** for privileged accounts.

### SMB Security
- Restrict **SMB share permissions** to **least privilege**.
- Audit SMB share access to detect unauthorized activity.

### Active Directory Hardening
- **Review delegation settings** and transition to **resource-based delegation (RBCD)**.
- Secure **gMSA accounts** by restricting `ReadGMSAPassword` permissions.
- Regularly audit **privileged group memberships**.

### Kerberos & NTLM Protections
- Disable **NTLMv2** where possible and enforce **Kerberos authentication**.
- Remove **unconstrained delegation** and limit `AllowedToDelegate` usage.
- Enable **Kerberos policy settings** to prevent delegation abuse.

### Logging & Monitoring
- Enable **DNS logging** to track unauthorized modifications.
- Implement **SIEM solutions** to detect authentication anomalies.
- Use **BloodHound** for continuous risk assessment and privilege escalation tracking.

## Internal Network Compromise Walkthrough
The tester successfully compromised the internal network and gained **full administrative control** over the `intelligence.htb` Active Directory domain. Below are the detailed steps taken:

### Step 1: Initial Access via Web Application
- **Port 80** hosted a publicly accessible website with a **predictable naming convention**.
- A **Python script** was created to fuzz for similar names, revealing a **default password**.

### Step 2: Password Spray & SMB Enumeration
- Used **`netexec`** to perform a **password spray attack**, gaining access to **Tiffany.molina**.
- **SMB enumeration** with `smbmap` revealed:
  - `IT` and `Users` shares with **read access**.
  - A **PowerShell script** in the `IT` share (privileged operation of `Ted.graves`).
  - `user.txt` flag in Tiffany’s home directory.

### Step 3: DNS Enumeration & NTLM Capture
- The **PowerShell script** was used to query DNS entries starting with `Web*`.
- Created a **malicious DNS entry** and used **Responder** to capture **Ted.graves' NTLMv2 hash**.
- Cracked the hash offline using **hashcat**.

### Step 4: Active Directory Enumeration & Exploitation
- **BloodHound-Python** was used to gather AD information.
- Found that **Ted.graves** belonged to **ITSupport**, which had **ReadGMSAPassword** on `svc_int$`.
- Used **gMSADumper** to retrieve the **NTLM hash of svc_int$**.

### Step 5: Kerberos Delegation Abuse & Domain Admin Compromise
- `svc_int$` had **AllowedToDelegate** enabled.
- Used `impacket-getST` to **forge a Kerberos service ticket** and impersonate **Administrator**.
- Gained **full domain controller access**.

---

This write-up details the successful compromise of `intelligence.htb` and provides actionable security recommendations to prevent future exploitation.


