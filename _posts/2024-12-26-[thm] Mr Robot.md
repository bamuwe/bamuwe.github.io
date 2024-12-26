---
title: '[thm] Mr Robot'
date: 2024-12-26 20:25 +0800
categories: [hack,TryHackMe]
tags: []
---

![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-1.png>)

## information

![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-2.png>)
> 端口扫描

![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-3.png>)
这个页面有点炫酷，一开始搞得我还蛮尴尬，因为一上来就开扫，整的范围很大，一时间难以聚集攻击向量。啊拉巴拉不说，一口价，`robots.txt`

![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-4.png>)
> wget http://10.10.51.179/fsocity.dic

获得了**key1**，同时下载到一个字典。这个字典做一个处理.
![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-5.png>)
> 这个字典有大量的重复项。

通过扫描可以看出这是一个`wordpress`站点，但是没有明显的1day。考虑对后台进行爆破。
![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-6.png>)

跟他爆了！
这里用的`ffuf`爆破，截图就省略了。使用先前获得的字典，用户名密码依次爆破，最后得到。
**elliot/ER28-0652**
![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-7.png>)
得到后台，同时我们是`administrator`权限。


## user1

![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-8.png>)
修改`404`页面为`php-reverse-shell.php`
![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-9.png>)
get shell.
![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-10.png>)
家目录下获得密码hash和**key2**
![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-11.png>)
换rockyou爆破出来密码。
`c3fcd3d76192e4007dfb496cca67e13b:abcdefghijklmnopqrstuvwxyz`
## user2

![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-12.png>)
**robot/abcdefghijklmnopqrstuvwxyz**

## root

`suid-nmap`一把梭。
![alt text](<../assets/img/2024-12-26-[thm] Mr Robot.assets/image-13.png>)
> own~

## conclusion
- 渗透枚举基本功
- 全面枚举后明确攻击向量





