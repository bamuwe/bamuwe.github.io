---
title: '[thm] Kenobi'
date: 2024-12-26 16:15 +0800
categories: [hack,TryHackMe]
tags: [rpcbind]
---

![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image.png>)

## information

![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-1.png>)
> 端口扫描

这里重点关注`ftp`和`smb`服务。
![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-2.png>)
ftp服务且版本为`ProFTPD 1.3.5`

![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-3.png>)
匿名用户登录`smb`服务，可以获得一个`log.txt`文件。文件大致内容如下：

```sh 
Enter same passphrase again:                                                                                   [297/375]
Your identification has been saved in /home/kenobi/.ssh/id_rsa.                                                         
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.                                                         The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi                                                        The key's randomart image is:
+---[RSA 2048]----+
|                 |
|           ..    |
|        . o. .   |
|       ..=o +.   |
|      . So.o++o. |
|  o ...+oo.Bo*o  |
| o o ..o.o+.@oo  |
|  . . . E .O+= . |
|     . .   oBo.  |
+----[SHA256]-----+

# This is a basic ProFTPD configuration file (rename it to
# 'proftpd.conf' for actual use.  It establishes a single server                                                        # and a single anonymous login.  It assumes that you have a user/group                                                  # "nobody" and "ftp" for normal operation and anon.

ServerName                      "ProFTPD Default Installation"                                                          ServerType                      standalone
DefaultServer                   on

# Port 21 is the standard FTP port.
Port                            21

# Don't use IPv6 support by default.
UseIPv6                         off

# Umask 022 is a good standard umask to prevent new dirs and files                                                      # from being group and world writable.
etc...
```

> 大致是kenobi用户生成了一个密钥，同时给出了服务的一些信息。

![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-4.png>)
> rpcbind服务的扫描，这里我直接使用room给出的命令。

## user1

![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-5.png>)
通过信息收集，我们可以发现`ProFTPd 1.3.5`是一个存在漏洞的版本
该漏洞可以实现文件的复制。
思路清晰：先使用1day移动`kenobio`用户的密钥到`/var`目录下，再在本地挂载，获得`id_rsa`
![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-6.png>)
> 成功复制了id_rsa

`mount 10.10.21.198:/var /mnt/Kenobi`
![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-7.png>)
获得用户 **kenobi**

## root

根据room的提示，这里是一个`suid`提权。
![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-8.png>)
> find / -perm -u=s -type f 2>/dev/null

问题文件是`/usr/bin/menu`。使用`strings`命令进行一个大致的分析。
![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-9.png>)
这里使用的是相对路径，所以我们可以尝试劫持环境变量提权。
![alt text](<../assets/img/2024-12-26-[thm] Kenobi.assets/image-10.png>)
也是成功走你了。

## conclution

- 知识面的广度决定攻击面的广度。
- 总结非常重要，`rpcbind`的利用在以前的打靶过程中遇到过，但是如果让我0-1去做的话，大概率还是会卡在那里。

