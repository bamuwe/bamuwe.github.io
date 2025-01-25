---
title: '[thm] TryHack3M_Bricks_Heist'
date: 2025-01-25 20:42 +0800
categories: [hack,TryHackMe]
tags: []
---

## information

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image.png>)
> port scan

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-16.png>)

通过网站icon发现是wordpress网站，可以使用wpscan扫描。这里我直接用nuclei扫描了。
上次打靶机的时候群友用了一次nuclei，发现效率挺高的哈哈~~（不是偷懒）~~

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-2.png>)

有一个现成的ndayRce。

## user1
![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-3.png>)

反弹一个shell回来，外围打点就算结束了hah。接下来才是超模的开始。

## What is the name of the suspicious process?

这里给的场景是中了挖矿病毒，我第一个想法是看top里面cpu占用之类的，但是吧，这里没tty。想尝试ps -aux。奈何目视大法不管用，太多了，我哪知道哪个是哪个，更好的解决办法（看wp），是先做下一题。

Answer:**nm-inet-dialog**
## What is the service name affiliated with the suspicious process?

ps -aux 是用来查看进程之类项目，而服务要使用systemctl来查看。
`systemctl list-units --type=service --state=running`

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-4.png>)

有一个奇怪的名称。接着查看细节。这里对于服务的检查还是我比较陌生的部分，头一次接触。

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-5.png>)

Answer:**ubuntu.service**
应该是使用服务维权之类的办法。

## What is the log file name of the miner instance?

查看日志，按照思路，到对应的目录下面看看。

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-6.png>)

想看看conf有没有配置日志位置，然后发现，里面的内容很像日志，还真是。
所以这应该是一个，挖矿木马伪造成这个命令🤔

## What is the wallet address of the miner instance?

矿机钱包地址是什么，这个问题一出来就感觉陌生了hah
但是日志里有一串id，怀疑是交易id

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-7.png>)

事实证明我想对了，但是败在经验不足。这里要处理一下。

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-8.png>)

用cyberchef的magic解密就可以得到妙妙密码。
`bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qabc1qyk79fcp9had5kreprce89tkh4wrtl8avt4l67qa`
但是——作为钱包地址这里太长了。观察一下可以发现，这里的`bc1qyk`是有重复的，就把这个作为开头尝试一下。

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-9.png>)

于是我们得到了`bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-10.png>)

艾玛，看到这里真的是有意思🐕突然就有大黑客的感觉了。

Answer:**bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa**

## The wallet address used has been involved in transactions between wallets belonging to which threat group?

在小小的链上掏啊掏啊掏。开玩笑的，掏不来一点!

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-11.png>)

看到最开始有一笔11btc的交易。~~说实话，有点馋，这11btc打我钱包里我直接躺平了吧（maybe）~~
得到交易id$50a89a628a6620216dca19f1221c138982601810fd60677ac7612a01999ae028$

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-12.png>)

多个钱包向`bc1q5jqgm7nvrhaw2rh2vk0dk8e4gg5g373g0vz07r`转账。

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-13.png>)

应该就是了，然后Google一下。

![alt text](<../assets/img/2025-01-25-[thm] TryHack3M_Bricks_Heist.assets/image-15.png>)

Answer:**LockBit**

## conlusion

- 服务和进程不同的检测方法。
- 头一回尝试做区块链安全相关的尝试，有点有趣哈哈。