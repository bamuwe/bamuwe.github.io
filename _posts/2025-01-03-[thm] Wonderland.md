---
title: '[thm] Wonderland'
date: 2025-01-03 15:31 +0800
categories: [hack,TryHackMe]
tags: []
---

## information
![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image.png>)
> port scan

![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-1.png>)
目录枚举发现特别的路径<http://wonderland.thm/r/a/b/b/i/t>

![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-3.png>)

## user1

通过web源代码获得用户凭据**alice:HowDothTheLittleCrocodileImproveHisShiningTail**

![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-4.png>)

## user2

![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-5.png>)
劫持python模块提权

## user3

![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-6.png>)
再rabbit的目录下发现有一个teaParty文件，下载下来分析。
这里改变权限到1003，再运行一个命令，尝试劫持环境变量提权。
![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-7.png>)

![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-8.png>)
用户目录下有一个password.txt文件。尝试可以知道是用户自己的密码。

## root

偷看wp。
![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-9.png>)
解释一下这里就是赋予了perl更改uid的权限，同时在执行时生效。这个检测功能之前的linpeas.sh好像是没有的，之气那用的是另一个东西，叫啥忘记了，也是只能一个一个扫描。
![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-10.png>)
![alt text](<../assets/img/2025-01-03-[thm] Wonderland.assets/image-11.png>)
用原来提升权限的shell没法提权到root，重新ssh开了个shell就没问题了。

## conclusion

- 靶机和实战还是有很多差别的。代入靶机思维能够很好的帮助我们发现攻击向量。