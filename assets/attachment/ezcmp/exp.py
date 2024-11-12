from pwn import *
io = remote('node5.anna.nssctf.cn',25405)
#io = gdb.debug('./ezcmp','b *0x4014b4')
io.sendline(p64(0x144678aadc0e4072)+p64(0x84b6e81a4c7eb0e2)+p64(0xf426588abcee2052)+p64(0xc8cb2c5e90c2))
io.interactive()
