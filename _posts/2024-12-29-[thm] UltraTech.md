---
title: '[thm] UltraTech'
date: 2024-12-29 12:31 +0800
categories: [hack,TryHackMe]
tags: []
---

## information

![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image.png>)
> port scan

优化一下工作流，这个rustscan真的快。（以前🧌推荐的）

![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-1.png>)
> robots.txt

robots.txt中发现一个site_map路径。

![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-2.png>)
没啥用啊
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-5.png>)
网站的主页也只有一个登录页面看起来能做文章。
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-4.png>)
对8081端口进行枚举，发现了两个可能能利用的路径，一个auth，经过尝试应该和31331端口的是一个接口，ping目录访问直接是500。
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-6.png>)
node不是很会，问了下ChatGPT
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-7.png>)
大概就是缺少变量，枚举一下
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-3.png>)
ip?尝试下远程文件包含。
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-8.png>)
无果，rce也没啥说法。LFI？
诶，不好意思，有果
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-9.png>)
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-10.png>)
> heiheihei

卡住了，咋不行捏。rce咋打不进去，wget下来的都无法访问到。
回头看一眼爆破还以为有成果，只能说是依托
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-11.png>)
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-12.png>)
> 那我问你，我申气了。

## user1

![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-13.png>)
（偷偷看wp）我去，原来如此。好吧，是我的问题。
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-15.png>)
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-14.png>)
下载了再在本地执行bash。

## user2

![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-16.png>)
来了老弟。
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-17.png>)
md5爆破
获得网页的后台**r00t:n100906**
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-18.png>)
提示我们要看config。
![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-19.png>)
> find / -name *config 2>/dev/null|grep -v 'snap'|grep -v 'lib'|grep -v 'src'|grep -v 'sys'|grep -v 'etc'|grep -v 'bin'

我愿称之为力大飞砖⬆️
没权限...不过我们r00t用户的密码倒是一样的，直接横向。

![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-20.png>)
> 刚刚看wp不小心看见好像有ftp什么事，突然想起来了hah。但是没🥚用

## root

![alt text](<../assets/img/2024-12-29-[thm] UltraTech.assets/image-21.png>)
> docker run -v /:/mnt --rm -it bash chroot /mnt sh

突然注意到是docker用户，hin快啊。咋不对捏，就对！

## conclution
- 比较考验基本功，一直枚举。