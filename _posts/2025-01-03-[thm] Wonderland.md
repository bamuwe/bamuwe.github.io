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