+++
date = '2025-04-23T04:15:47+01:00'
draft = false
title = 'Cronos'
+++

#  Internal Penetration Test Report: **CRONOS**

---

##  Summary

- **Author:** blackcaesar0  
- **Team:** OSI  
- **Machine:** Cronos  
- **Difficulty:** Medium  
- **Assessment Date:** April 23, 2025  
- **Assessment Window:** 02:15 AM – 02:59 AM  
- **Assessment Type:** Black-box  
- **Scope:** Internal (simulated corporate environment)

---

##  Executive Summary

The internal penetration test targeted the **CRONOS** machine on the Hack The Box platform. The objective was to simulate an external attacker with no prior access or credentials and identify potential vulnerabilities that could be exploited to gain unauthorized access and escalate privileges.

Key vulnerabilities identified:

- **DNS Zone Transfer**: Misconfigured DNS allowed unauthorized zone transfers, revealing internal subdomains.
- **SQL Injection**: The admin login portal was susceptible to SQL injection, allowing authentication bypass.
- **Command Injection**: The web application's traceroute and ping functionalities were vulnerable to command injection.
- **Privilege Escalation via Cron Job**: A misconfigured cron job executed a script owned by a non-privileged user, allowing privilege escalation to root.

---

##  Assessment Methodology

1. **Reconnaissance**  
   - Port scanning using Nmap to identify open services.
   - DNS enumeration to discover subdomains.

2. **Enumeration**  
   - Web application analysis to identify potential entry points.
   - Directory and file fuzzing to uncover hidden resources.

3. **Exploitation**  
   - SQL injection to bypass authentication.
   - Command injection to gain initial shell access.

4. **Privilege Escalation**  
   - Analysis of scheduled tasks and file permissions.
   - Exploitation of misconfigured cron job to gain root access.

5. **Reporting**  
   - Documentation of findings with recommendations for remediation.

---

##  Scope of Engagement

| **IP Address** | **Domains in Scope**         |
| -------------- | ---------------------------- |
| 10.129.148.80  | cronos.htb, admin.cronos.htb |

---

##  Key Findings Summary

| #   | Vulnerability                     | Risk Level | Description                                     | Exploited? |
| --- | --------------------------------- | ---------- | ----------------------------------------------- | ---------- |
| 1   | DNS Zone Transfer                 | Medium     | Unauthorized zone transfer revealing subdomains | ✅          |
| 2   | SQL Injection                     | High       | Authentication bypass via SQL injection         | ✅          |
| 3   | Command Injection                 | High       | Remote code execution through command injection | ✅          |
| 4   | Privilege Escalation via Cron Job | High       | Root access through misconfigured cron job      | ✅          |

---

##  Detailed Findings

### 1. DNS Zone Transfer

- **Risk Level:** Medium  
- **Description:** The DNS server allowed unauthorized zone transfers, revealing internal subdomains such as `admin.cronos.htb`.  
- **Impact:** Exposure of internal infrastructure details, aiding further attacks.  
- **Recommendation:** Restrict DNS zone transfers to authorized hosts only.

### 2. SQL Injection in Admin Login

- **Risk Level:** High  
- **Location:** `admin.cronos.htb` login portal  
- **Description:** The login form was vulnerable to SQL injection, allowing attackers to bypass authentication using payloads like `' OR 1=1 --`.  
- **Impact:** Unauthorized access to administrative functionalities.  
- **Recommendation:** Implement prepared statements and input validation to prevent SQL injection.

### 3. Command Injection in Traceroute and Ping Functions

- **Risk Level:** High  
- **Description:** The web application's traceroute and ping functionalities did not properly sanitize user input, allowing command injection. For example, inputting `8.8.8.8; whoami` executed the `whoami` command on the server.  
- **Impact:** Remote code execution with the privileges of the web server user.  
- **Recommendation:** Sanitize and validate all user inputs, and avoid using system calls with unsanitized input.

### 4. Privilege Escalation via Misconfigured Cron Job

- **Risk Level:** High  
- **Description:** A cron job executed a script (`/var/www/laravel/artisan`) every minute with root privileges. This script was owned by the web server user (`www-data`), allowing modification. Replacing it with a reverse shell script granted root access.  
- **Impact:** Full system compromise.  
- **Recommendation:** Ensure that scripts executed by cron jobs are owned by root and have appropriate permissions to prevent unauthorized modifications.

---

##  Lessons Learned

- **DNS Security:** Properly configure DNS servers to prevent unauthorized zone transfers.
- **Input Validation:** Always validate and sanitize user inputs to prevent injection attacks.
- **Least Privilege Principle:** Limit the permissions of users and services to the minimum necessary.
- **Secure Scheduled Tasks:** Ensure that cron jobs and other scheduled tasks do not execute scripts that can be modified by non-privileged users.

---

##  Recommendations Summary

| Vulnerability             | Recommendation                               |
|---------------------------|----------------------------------------------|
| DNS Zone Transfer         | Restrict zone transfers to authorized hosts  |
| SQL Injection             | Use prepared statements and input validation |
| Command Injection         | Sanitize user inputs and avoid unsafe system calls |
| Privilege Escalation via Cron Job | Secure cron job scripts with proper ownership and permissions |

---

##  Appendix

- **Nmap Scan Results:**

![nmap scan](/static/cronos/nmap_scan.jpg)

- **web enumeration:**

![subdomain](/static/cronos/subdomain_enum.jpg)

![website](/static/cronos/web_site.jpg)

- **SQL Injection:**

![sql injection](/static/cronos/sqli.jpg)

- **vulnerable code:**

![source code](/static/cronos/sqli_source_code.jpg)

- **OS command injection:**

![os command injection](/static/cronos/os_command_injection.jpg)

![command exec](/static/cronos/poc_os_command_injection.jpg)

- **Reverse Shell :**

![rev shell payload](/static/cronos/os_command_rev_shell.jpg)

![rev shell](/static/cronos/rev_shell_as_www-data.jpg)

- **Cron Job Entry:**

![cron jobs](/static/cronos/cron_jobs.jpg)

![priv enum](/static/cronos/priv_enum.jpg)

![root](/static/cronos/root_access.jpg)

-------------

*Note: This report is based on the analysis of the Cronos machine from Hack The Box. The vulnerabilities and configurations described are specific to this environment and may not reflect real-world systems.*

