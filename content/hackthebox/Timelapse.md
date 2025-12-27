+++
date = '2025-02-11T06:16:11+01:00'
draft = false
title = 'Timelapse'
+++
# Comprehensive Penetration Testing Report: Timelapse HTB Machine

## 1. Introduction
This report details the findings of a penetration test conducted on the Timelapse HTB machine. The objective was to identify vulnerabilities, exploit them, and provide recommendations for remediation. The target system was a Windows-based Active Directory environment with multiple services exposed.

---

## 2. Scope
The scope of the engagement included the following target:

| IP             | Domain                             |
| -------------- | ---------------------------------- |
| 10.129.227.113 | timelapse.htb / dc01.timelapse.htb |

---

## 3. Methodology
The penetration test followed a structured methodology:
1. **Reconnaissance**: Enumeration of open ports, services, and domains.
2. **Exploitation**: Gaining initial access through identified vulnerabilities.
3. **Privilege Escalation**: Escalating privileges to gain administrative access.
4. **Post-Exploitation**: Enumerating the environment and identifying misconfigurations.
5. **Reporting**: Documenting findings and providing remediation recommendations.

---

## 4. Findings

### 4.1 Reconnaissance
#### 4.1.1 Nmap Scan Results
A full port scan revealed the following services:
- **DNS (53/tcp)**: Active Directory domain controller.
- **Kerberos (88/tcp)**: Used for authentication.
- **LDAP (389/tcp, 636/tcp, 3268/tcp, 3269/tcp)**: Active Directory LDAP services.
- **SMB (445/tcp)**: File sharing service with guest access enabled.
- **WinRM (5986/tcp)**: Windows Remote Management service.

#### 4.1.2 SMB Enumeration
- Guest access was enabled on the SMB share `Shares`.
- A file named `winrm_backup.zip` was discovered in the `dev` directory.

#### 4.1.3 Username Enumeration
Using `netexec`, the following users and groups were identified:
- Notable users: `legacyy`, `svc_deploy`, `Administrator`.
- Notable groups: `LAPS_Readers`, `Domain Admins`.

---

### 4.2 Exploitation
#### 4.2.1 Cracking the ZIP File
- The `winrm_backup.zip` file was password-protected.
- Using `zip2john`, the hash was extracted and cracked with `john` and the `rockyou.txt` wordlist, revealing the password: `suprem*****`.

#### 4.2.2 Extracting the PFX File
- The ZIP file contained a PFX file (`legacyy_dev_auth.pfx`), which was also password-protected.
- Using `pfx2john`, the hash was extracted and cracked with `john`, revealing the password: `thugl*****`.

#### 4.2.3 Extracting Certificates and Keys
- The PFX file was decrypted using OpenSSL to extract the private key (`decrypted_private.key`) and certificate (`legacyy_dev_auth.crt`).

#### 4.2.4 Gaining Initial Access
- Using `evil-winrm` with the extracted private key and certificate, access was gained as the user `legacyy`.

---

### 4.3 Privilege Escalation
#### 4.3.1 Enumerating PowerShell History
- The PowerShell history file (`ConsoleHost_history.txt`) revealed credentials for the `svc_deploy` user:
  - Username: `svc_deploy`
  - Password: `E3R$Q62^12**********`

#### 4.3.2 Enumerating svc_deploy Privileges
- The `svc_deploy` user was a member of the `LAPS_Readers` group, which allowed reading the Local Administrator Password Solution (LAPS) password for the domain controller.

#### 4.3.3 Extracting LAPS Password
- Using the `Get-ADComputer` command, the LAPS password for `DC01` was retrieved:
  - Password: `@t%va&Bk@;*********`

#### 4.3.4 Gaining Administrative Access
- Using `evil-winrm` with the extracted LAPS password, administrative access was gained as the `Administrator` user.

---

## 5. Post-Exploitation
- Full control over the domain controller was achieved.
- The following misconfigurations were identified:
  1. **Guest Access on SMB Share**: Allowed unauthorized access to sensitive files.
  2. **Weak Passwords**: Passwords for the ZIP and PFX files were easily crackable.
  3. **LAPS Misconfiguration**: The `svc_deploy` user had excessive privileges, allowing access to the LAPS password.

---

## 6. Recommendations and Remediation

### 6.1 SMB Share Configuration
- **Disable Guest Access**: Restrict access to SMB shares to authenticated users only.
- **Implement Access Controls**: Ensure that only authorized users can access sensitive directories.

### 6.2 Password Policies
- **Enforce Strong Passwords**: Implement a password policy requiring complex passwords for all accounts and files.
- **Regular Password Audits**: Conduct regular audits to identify and remediate weak passwords.

### 6.3 LAPS Configuration
- **Restrict LAPS_Readers Group**: Ensure that only necessary users have access to the `LAPS_Readers` group.
- **Monitor LAPS Usage**: Log and monitor access to LAPS passwords to detect unauthorized access.

### 6.4 Certificate Management
- **Secure PFX Files**: Store PFX files in a secure location with restricted access.
- **Rotate Certificates**: Regularly rotate certificates and keys to mitigate the risk of compromise.

### 6.5 PowerShell Security
- **Clear Command History**: Implement a policy to clear PowerShell command history regularly.
- **Restrict PowerShell Usage**: Limit PowerShell usage to authorized users and scripts.

### 6.6 Network Hardening
- **Disable Unnecessary Services**: Disable or restrict access to services like WinRM and SMB if not required.
- **Implement Network Segmentation**: Segment the network to limit lateral movement in case of a breach.

---

## 7. Conclusion
The Timelapse HTB machine was successfully compromised due to multiple misconfigurations and weak security practices. By implementing the recommended remediation steps, the security posture of the environment can be significantly improved to prevent similar attacks in the future.

---

## 8. Appendices
### 8.1 Tools Used
- Nmap
- Netexec (CrackMapExec)
- John the Ripper
- OpenSSL
- Evil-WinRM

### 8.2 References
- [Microsoft LAPS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [SMB Security Best Practices](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [PowerShell Security Guidelines](https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/security-guidelines?view=powershell-7.3)

---
