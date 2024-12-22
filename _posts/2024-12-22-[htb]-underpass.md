---
title: '[htb] underpass'
date: 2024-12-22 12:39 +0800
categories: [hack,HackTheBox]
tags: []
---

## information

```sh
╭─bamuwe@Mac ~/Desktop
╰─$ nmap -F underpass.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2024-12-22 12:41 CST
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.12s latency).
Not shown: 98 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.92 seconds
```

![image-20241222124520698](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222124520698.png)

> 网站显示是apache的默认页面

这里应该是唯一会卡的点了，一开始我的字典里没有对应的目录，扫不出来。

![image-20241222124705685](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222124705685.png)

> 存在一个名为daloradius的应用。

![image-20241222124759370](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222124759370.png)

> <https://github.com/lirantal/daloradius>

上github看看目录结构。可以得到如下的管理员登录页面。

![image-20241222124841326](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222124841326.png)

> <http://underpass.htb/daloradius/app/operators/login.php>

## user1

没有密码？怎么办

![image-20241222125030932](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222125030932.png)

那没办法了，直接给我送脸上了。

![image-20241222125920831](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222125920831.png)

> 后台页面。因为我打的是免费服务器，有时候这里会刷新不出来

## user2

![image-20241222130012886](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222130012886.png)

> 用户列表

搜索可得，radius用md5加密用户密码，我们也使用md5去解密。

![image-20241222130203083](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222130203083.png)

> hashcat破解

**svcMosh:underwaterfriends**

这密码这么瘆人呢。

![image-20241222130259703](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222130259703.png)

> 也是进来了

## root

![image-20241222130323995](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222130323995.png)

这是什么？搜一下

![image-20241222130430345](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222130430345.png)

 有点类似putty的那种意思。后文也说明了怎么使用

![image-20241222130523850](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222130523850.png)

> <https://www.cnblogs.com/sunweiye/p/12003616.html>

思路清楚，用root开一个shell接着连上去，跟着敲命令就完事了。

![image-20241222130729594](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222130729594.png)

> 请你跟我这样做～我就跟你这样做。

![image-20241222130643329](../assets/img/2024-12-22-%5Bhtb%5D-underpass.assets/image-20241222130643329.png)

> own～

## conclusion

- 渗透的本质是信息收集，枚举的广度决定渗透的深度。
- **“The breadth of enumeration determines the depth of exploitation.”**
