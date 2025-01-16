---
title: '[thm] Silver Platter'
date: 2025-01-16 22:54 +0800
categories: [Hack,TryHackMe]
tags: []
---

## information

![alt text](<../assets/img/2025-01-16-[thm] s.assets/image-9.png>)
> port scan

![alt text](<../assets/img/2025-01-16-[thm] s.assets/image-8.png>)
浏览网页这里有提到一个网页应用，这里踩了一个大坑，因为linux下是区分大小写的，而我直接复制粘贴是没法访问这个网页。

![alt text](<../assets/img/2025-01-16-[thm] s.assets/image-1.png>)
查找发现这个网页应用存在登录绕过

![alt text](<../assets/img/2025-01-16-[thm] s.assets/image-2.png>)
> <https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d>

![alt text](<../assets/img/2025-01-16-[thm] s.assets/image-4.png>)
> <https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2023-47323>

同时存在一个越权（？）可以查看其他用户的消息。但是我们本身就是administrator能看也很合理吧🐶
![alt text](<../assets/img/2025-01-16-[thm] s.assets/image-3.png>)

## user1

user1**tim:cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol**

![alt text](<../assets/img/2025-01-16-[thm] s.assets/image-6.png>)
> $cat /var/log/auth* | grep -i pass
获得的tim用户是adm组，可以查看日志。
user2**tyler : _Zd_zx7N823/**

![alt text](<../assets/img/2025-01-16-[thm] s.assets/image-7.png>)
> own!

## conclusion

- 被大小写卡我也是没想到的。
- 查看日志提权。