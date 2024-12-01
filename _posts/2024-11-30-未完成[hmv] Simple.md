---
title: '[hmv] Simple'
date: 2024-11-30 18:56 +0800
categories: [hack,HackMyVm]
tags: [windows]
---

未完成❎


# information

```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-30 18:51 CST
Nmap scan report for Simple (192.168.1.193)
Host is up (0.0081s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE    SERVICE         VERSION
80/tcp   open     http            Microsoft IIS httpd 10.0
|_http-title: Simple
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open     msrpc           Microsoft Windows RPC
139/tcp  open     netbios-ssn     Microsoft Windows netbios-ssn
445/tcp  open     microsoft-ds?
5985/tcp open     http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7000/tcp filtered afs3-fileserver
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: SIMPLE, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:62:16:7e (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| smb2-time:
|   date: 2024-11-30T10:51:00
|_  start_date: N/A
|_clock-skew: -17s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.97 seconds
```

