> 环境：Windows10 1903
>
> 工具：Windbg x86

&emsp;&emsp;<font size=2>标题看上去吓人了一些，其实我对Windows的了解并不深，但绝不是标题党。出于复现堆漏洞CVE的目标，我还是研究了一下Windows下的堆结构，然后就有了这篇文章，当然我也不是自己探索出来的，有参考过一篇文章[windows10下的堆结构及unlink分析](https://zhuanlan.zhihu.com/p/44456002)，这篇文章的关键思路都不错，帮助我对堆有了一个大致的思想准备，但是还是不够详细，就不得不让我这个新手来写一写白话文了。</font></br>

&emsp;&emsp;<font size=2>首先我们都知道Window是闭源的，因此不可能像Linux那样对着源码直接调代码理解就行了。因此这更偏向于一种黑盒调试的感觉，除了靠摸索着前辈们的文章慢慢调试堆块分析逻辑之外，我们还可以用windbg这个微软亲弟弟调试器来辅助我们了解一些结构体去猜测源函数的逻辑，接下来先让我们来看一看前辈们已经得出的结论：</font></br>

- Windows下的堆块在release版和Debug版的表现不同，在调试态和常规态表现也不同，还可能与系统和编译器有关；
- 调试态的堆不使用快表只使用空表，所有堆块被加上16字节防止溢出并分别为8字节的0xAB和8字节的0x00，块首的标识位也不同；
- 只有使用可扩展堆的时候快表才会被启用，即`HeapCreate()`的第三个参数`dwMaximumSize`为0；
- Windows的堆块头都是经过加密的，由`_HEAP_ENTRY`偏移0x50处的8个字节对每个堆块头进行的异或；

&emsp;&emsp;<font size=2>有了这些结论，我们就可以着手亲自探索Windows未开源的堆了，虽然难但是其乐无穷。接下来开始就是靠经验逆了，分析过程中不会把过多细节都贴出来的，但是理解Windows堆块及其利用绝对绰绰有余。先从以下源码开始看吧：</font></br>

```C
#include <windows.h>
#include <stdio.h>

int main()
{
    PVOID p0,p1,p2,p3,p4,p5,p6,p7,p8;
    HANDLE hp=HeapCreate(HEAP_NO_SERIALIZE,0x1000,0x10000);

    p1=HeapAlloc(hp,HEAP_NO_SERIALIZE,3);
    HeapAlloc(hp,HEAP_NO_SERIALIZE,3);
    p2=HeapAlloc(hp,HEAP_NO_SERIALIZE,4);
    HeapAlloc(hp,HEAP_NO_SERIALIZE,4);
    p3=HeapAlloc(hp,HEAP_NO_SERIALIZE,5);
    HeapAlloc(hp,HEAP_NO_SERIALIZE,5);
    p4=HeapAlloc(hp,HEAP_NO_SERIALIZE,6);
    HeapAlloc(hp,HEAP_NO_SERIALIZE,6);


    HeapFree(hp,HEAP_NO_SERIALIZE,p1);
    HeapFree(hp,HEAP_NO_SERIALIZE,p2);
    HeapFree(hp,HEAP_NO_SERIALIZE,p3);
    HeapFree(hp,HEAP_NO_SERIALIZE,p4);
    __asm int 3

    return 0;
}
```

&emsp;&emsp;<font size=2>别忘了用`__asm int 3`来手动插入断点，如果直接用调试器打开程序的话那就是调试态堆了，用attach的方法堆区就不是在调试态被初始化，分配模式也就不是debug了。编译选项别忘了选release版，然后直接运行之，即时调试器（windbg）就会attach上去，这个时候堆区是这样的：</font></br>

```
Microsoft (R) Windows Debugger Version 10.0.18362.1 X86
Copyright (c) Microsoft Corporation. All rights reserved.

*** wait with pending attach
Symbol search path is: srv*
Executable search path is: 
ModLoad: 01080000 01096000   C:\Users\fanda\Desktop\heap.exe
ModLoad: 77d70000 77ef2000   C:\Windows\SYSTEM32\ntdll.dll
ModLoad: 754c0000 755a0000   C:\Windows\System32\KERNEL32.DLL
ModLoad: 74b60000 74d01000   C:\Windows\System32\KERNELBASE.dll
(3c0.191c): Break instruction exception - code 80000003 (!!! second chance !!!)
*** WARNING: Unable to verify checksum for C:\Users\fanda\Desktop\heap.exe
eax=00000001 ebx=00c03000 ecx=fcc42d06 edx=00000002 esi=00f12cf0 edi=00f14fa8
eip=010810d7 esp=00bbfb8c ebp=00bbfba0 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
heap+0x10d7:
010810d7 cc              int     3
0:000> !heap
        Heap Address      NT/Segment Heap

              f10000              NT Heap
             1150000              NT Heap
0:000> !heap -a 1150000
HEAPEXT: Unable to get address of ntdll!RtlpHeapInvalidBadAddress.
Index   Address  Name      Debugging options enabled
  2:   01150000 
    Segment at 01150000 to 01160000 (00001000 bytes committed)
    Flags:                00001001
    ForceFlags:           00000001
    Granularity:          8 bytes
    Segment Reserve:      00100000
    Segment Commit:       00002000
    DeCommit Block Thres: 00000200
    DeCommit Total Thres: 00002000
    Total Free Size:      00000164
    Max. Allocation Size: 7ffdefff
    Lock Variable at:     00000000
    Next TagIndex:        0000
    Maximum TagIndex:     0000
    Tag Entries:          00000000
    PsuedoTag Entries:    00000000
    Virtual Alloc List:   0115009c
    Uncommitted ranges:   0115008c
            01151000: 0000f000  (61440 bytes)
    FreeList[ 00 ] at 011500c0: 01150508 . 011504e8  
        011504e0: 00010 . 00010 [100] - free
        011504c0: 00010 . 00010 [100] - free
        011504a0: 00010 . 00010 [100] - free
        01150480: 00480 . 00010 [100] - free
        01150500: 00010 . 00ae0 [100] - free

    Segment00 at 01150000:
        Flags:           00000000
        Base:            01150000
        First Entry:     01150480
        Last Entry:      01160000
        Total Pages:     00000010
        Total UnCommit:  0000000f
        Largest UnCommit:00000000
        UnCommitted Ranges: (1)

    Heap entries for Segment00 in Heap 01150000
         address: psize . size  flags   state (requested size)
        01150000: 00000 . 00480 [101] - busy (47f)
        01150480: 00480 . 00010 [100]
        01150490: 00010 . 00010 [101] - busy (3)
        011504a0: 00010 . 00010 [100]
        011504b0: 00010 . 00010 [101] - busy (4)
        011504c0: 00010 . 00010 [100]
        011504d0: 00010 . 00010 [101] - busy (5)
        011504e0: 00010 . 00010 [100]
        011504f0: 00010 . 00010 [101] - busy (6)
        01150500: 00010 . 00ae0 [100]
        01150fe0: 00ae0 . 00020 [111] - busy (1d)
        01151000:      0000f000      - uncommitted bytes.

```

&emsp;&emsp;<font size=2>这就是我们释放了一系列的堆块后的情况，注意这里用的`HeapCreate`不是可扩展堆，块表是不启用的，因此堆块被释放了是真释放了，不会进入快表，接下来我们看看这些空闲堆是怎么组织的：</font></br>

```
0:000> dd 1150480
01150480  34334484 0000c720 01150508 011504a8
01150490  35324484 0d00c7b2 00000000 00000000
011504a0  34334484 0000c7b2 01150488 011504c8
011504b0  35324484 0c00c7b2 00000000 00000000
011504c0  34334484 0000c7b2 011504a8 011504e8
011504d0  35324484 0b00c7b2 00000000 00000000
011504e0  34334484 0000c7b2 011504c8 011500c0
011504f0  35324484 0a00c7b2 00000000 00000000
0:000> dd 1150500
01150500  6b3345da 0000c7b2 011500c0 01150488
01150510  00000000 00000000 00000000 00000000
01150520  00000000 00000000 00000000 00000000
01150530  00000000 00000000 00000000 00000000
01150540  00000000 00000000 00000000 00000000
01150550  00000000 00000000 00000000 00000000
01150560  00000000 00000000 00000000 00000000
01150570  00000000 00000000 00000000 00000000
0:000> dd 1150000
01150000  a7324416 0100c7b0 ffeeffee 00000000
01150010  011500a4 011500a4 01150000 01150000
01150020  00000010 01150480 01160000 0000000f
01150030  00000001 00000000 01150ff0 01150ff0
01150040  00001001 00000001 00000000 00100000
01150050  36334486 0000c7b0 00000000 0000fe00
01150060  eeffeeff 00100000 00002000 00000200
01150070  00002000 00000164 7ffdefff 02480002
```

&emsp;&emsp;<font size=2>我们可以看到堆块头乱七八糟的，这就是和`_HEAP_ENTRY`做了异或的结果，我们可以算一算，对于我们在`1150480`释放的堆应该是size为3的，而`34334484 ^ 36334486 = 0200002`，根据_HEAP_ENTRY结构：</font></br>

```
0:000> dt ntdll!_HEAP_ENTRY 1150480
   +0x000 UnpackedEntry    : _HEAP_UNPACKED_ENTRY
   +0x000 Size             : 0x4484
   +0x002 Flags            : 0x33 '3'
   +0x003 SmallTagIndex    : 0x34 '4'
   +0x000 SubSegmentCode   : 0x34334484
   +0x004 PreviousSize     : 0xc720
   +0x006 SegmentOffset    : 0 ''
   +0x006 LFHFlags         : 0 ''
   +0x007 UnusedBytes      : 0 ''
   +0x000 ExtendedEntry    : _HEAP_EXTENDED_ENTRY
   +0x000 FunctionIndex    : 0x4484
   +0x002 ContextValue     : 0x3433
   +0x000 InterceptorValue : 0x34334484
   +0x004 UnusedBytesLength : 0xc720
   +0x006 EntryOffset      : 0 ''
   +0x007 ExtendedBlockSignature : 0 ''
   +0x000 Code1            : 0x34334484
   +0x004 Code2            : 0xc720
   +0x006 Code3            : 0 ''
   +0x007 Code4            : 0 ''
   +0x004 Code234          : 0xc720

```

&emsp;&emsp;<font size=2>看的出来size为2，咦？怎么会这样？嘿嘿，32位Windows的size都是要乘上一个8才是真正的堆块大小的，因此是0x10，符合我们这里的堆块大小，这里的`SmallTagIndex`其实叫堆cookie，以后会讲。我们分析一下从`01150480 ~ 01150500`里被释放的堆块组织结构，我们可以得到以下结论：</font></br>

![单堆链](https://raw.githubusercontent.com/fangdada/ctf/master/how2pwn/Windows/RtlpHeapFree/SmallEmptyList/screenshot/单堆链.png)

&emsp;&emsp;<font size=2>如果我们用以下代码再运行一次：</font></br>

```C
#include <windows.h>
#include <stdio.h>

int main()
{
    PVOID p0,p1,p2,p3,p4,p5,p6,p7,p8;
    HANDLE hp=HeapCreate(HEAP_NO_SERIALIZE,0x1000,0x10000);

    p1=HeapAlloc(hp,HEAP_ZERO_MEMORY,3);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,3);
    p2=HeapAlloc(hp,HEAP_ZERO_MEMORY,4);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,4);
    p3=HeapAlloc(hp,HEAP_ZERO_MEMORY,5);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,5);
    p4=HeapAlloc(hp,HEAP_ZERO_MEMORY,6);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,6);

    p5=HeapAlloc(hp,HEAP_ZERO_MEMORY,9);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,9);
    p6=HeapAlloc(hp,HEAP_ZERO_MEMORY,10);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,10);
    p7=HeapAlloc(hp,HEAP_ZERO_MEMORY,11);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,11);
    p8=HeapAlloc(hp,HEAP_ZERO_MEMORY,12);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,12);


    HeapFree(hp,HEAP_NO_SERIALIZE,p1);
    HeapFree(hp,HEAP_NO_SERIALIZE,p2);
    HeapFree(hp,HEAP_NO_SERIALIZE,p3);
    HeapFree(hp,HEAP_NO_SERIALIZE,p4);

    HeapFree(hp,HEAP_NO_SERIALIZE,p5);
    HeapFree(hp,HEAP_NO_SERIALIZE,p6);
    HeapFree(hp,HEAP_NO_SERIALIZE,p7);
    HeapFree(hp,HEAP_NO_SERIALIZE,p8);
    __asm int 3

    return 0;
}
```

&emsp;&emsp;<font size=2>堆结构就是这样的：</font></br>

![双堆链](https://raw.githubusercontent.com/fangdada/ctf/master/how2pwn/Windows/RtlpHeapFree/SmallEmptyList/screenshot/双堆链.png)

![堆链结构](https://raw.githubusercontent.com/fangdada/ctf/master/how2pwn/Windows/RtlpHeapFree/SmallEmptyList/screenshot/堆链结构.png)

&emsp;&emsp;<font size=2>可以引申出空闲多堆链的结构：</font></br>

![多堆链结构](https://raw.githubusercontent.com/fangdada/ctf/master/how2pwn/Windows/RtlpHeapFree/SmallEmptyList/screenshot/多堆链.png)

&emsp;&emsp;<font size=2>空闲堆的组织结构就这样清晰了，然后我们就可以从单个堆块被释放的整个过程去理解一下这个堆是如何被组织成上面这个样子的，我们简单一下代码，这几行就够了：</font></br>

```C
#include <windows.h>
#include <stdio.h>

int main()
{
    PVOID p0,p1,p2,p3,p4,p5,p6,p7,p8;
    HANDLE hp=HeapCreate(HEAP_NO_SERIALIZE,0x1000,0x10000);

    p1=HeapAlloc(hp,HEAP_ZERO_MEMORY,3);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,3);
    p2=HeapAlloc(hp,HEAP_ZERO_MEMORY,4);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,4);


    HeapFree(hp,HEAP_NO_SERIALIZE,p1);
    __asm int 3

    HeapFree(hp,HEAP_NO_SERIALIZE,p2);

    return 0;
}
```

&emsp;&emsp;<font size=2>编译成release后，直接运行用windbg attach上去，接下来全都是用windbg的单步跟踪手动分析这一个堆块的释放过程。来到`HeapFree`函数的入口处，然后用`t`命令trace进去（有一些flag属性的判断我们先不管），可以发现最终调用了`RtlHeapFree`，这才是真正的`free`函数：</font></br>

```
0:000> 
eax=009c04a8 ebx=009c04a8 ecx=009c0000 edx=00000001 esi=009c04a0 edi=009c0000
eip=77db79c0 esp=006ff9a0 ebp=006ff9bc iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlFreeHeap+0xb0:
77db79c0 53              push    ebx
0:000> 
eax=009c04a8 ebx=009c04a8 ecx=009c0000 edx=00000001 esi=009c04a0 edi=009c0000
eip=77db79c1 esp=006ff99c ebp=006ff9bc iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlFreeHeap+0xb1:
77db79c1 56              push    esi
0:000> 
eax=009c04a8 ebx=009c04a8 ecx=009c0000 edx=00000001 esi=009c04a0 edi=009c0000
eip=77db79c2 esp=006ff998 ebp=006ff9bc iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlFreeHeap+0xb2:
77db79c2 83ca02          or      edx,2
0:000> 
eax=009c04a8 ebx=009c04a8 ecx=009c0000 edx=00000003 esi=009c04a0 edi=009c0000
eip=77db79c5 esp=006ff998 ebp=006ff9bc iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlFreeHeap+0xb5:
77db79c5 e8c6040000      call    ntdll!RtlpFreeHeap (77db7e90)
```

&emsp;&emsp;<font size=2>事实上`RtlpFreeHeap`这个函数是可以从IDA里F5看伪代码的，但对于这么大的一个函数用不用IDA都没什么意义了，都是一大堆未知变量拿头看也看不出结果来，不如直接用调试器慢慢调，整个思路会慢慢清晰起来。具体用IDA的方式也很简单：`用IDA打开C:\windows\sysWOW64\ntdll.dll，然后windbg里输入lmv命令查看ntdll的基址，在IDA里rebase到相应的基址，然后找到77db7e90就行了（windbg里call RtlpFreeHeap右边括号里的地址）。`</font></br>

&emsp;&emsp;<font size=2>然后我们继续用`t`继续步入`RtlpFreeHeap`函数，一条一条执行下去，接下来我们就看到了`解密堆块头`的部分(注：堆块基址可能跟以上不一样，因为上次虚拟机被我当成主机不小心关了Orz，但不影响堆块算法的分析）：</font></br>

```
eax=00000000 ebx=011804a0 ecx=01180000 edx=00000003 esi=00000003 edi=01180000
eip=77db88ed esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0xa5d:
77db88ed 8b4750          mov     eax,dword ptr [edi+50h] ds:002b:01180050=8692b504
0:000> 
eax=8692b504 ebx=011804a0 ecx=01180000 edx=00000003 esi=00000003 edi=01180000
eip=77db88f0 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0xa60:
77db88f0 3103            xor     dword ptr [ebx],eax  ds:002b:011804a0=8593b506
0:000> 
eax=8692b504 ebx=011804a0 ecx=01180000 edx=00000003 esi=00000003 edi=01180000
eip=77db88f2 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0xa62:
77db88f2 8a4302          mov     al,byte ptr [ebx+2]        ds:002b:011804a2=01
0:000> 
eax=8692b501 ebx=011804a0 ecx=01180000 edx=00000003 esi=00000003 edi=01180000
eip=77db88f5 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0xa65:
77db88f5 324301          xor     al,byte ptr [ebx+1]        ds:002b:011804a1=00
0:000> 
eax=8692b501 ebx=011804a0 ecx=01180000 edx=00000003 esi=00000003 edi=01180000
eip=77db88f8 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0xa68:
77db88f8 3203            xor     al,byte ptr [ebx]          ds:002b:011804a0=02
0:000> 
eax=8692b503 ebx=011804a0 ecx=01180000 edx=00000003 esi=00000003 edi=01180000
eip=77db88fa esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0xa6a:
77db88fa 384303          cmp     byte ptr [ebx+3],al        ds:002b:011804a3=03

```

&emsp;&emsp;<font size=2>从上面这几条trace结果里面我们可以看到堆块头前4个字节的异或解密与`HeapCookie`检查的部分。很直观吧？`edi`就是我们的`_HEAP`结构体，堆块头偏移为3的地方就是我们之前看到的`SmallTagIndex`，他与堆块前3个字节的异或对比，相等才是通过检查，否则：</font></br>

```
77db88fd 0f8486f6ffff    je      ntdll!RtlpFreeHeap+0xf9 (77db7f89)
77db8903 e9ce9d0400      jmp     ntdll!RtlpFreeHeap+0x4a846 (77e026d6)
........
77e026d6 51              push    ecx
77e026d7 8bd3            mov     edx,ebx
77e026d9 8bcf            mov     ecx,edi
77e026db e8a38d0400      call    ntdll!RtlpAnalyzeHeapFailure (77e4b483)
77e026e0 e9a458fbff      jmp     ntdll!RtlpFreeHeap+0xf9 (77db7f89)
```

&emsp;&emsp;<font size=2>然后我们继续往下走，解密第二个4字节：</font></br>

```
0:000> 
eax=00000002 ebx=011804a0 ecx=01180000 edx=00000002 esi=011804a2 edi=01180000
eip=77db8016 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x186:
77db8016 0fb74f54        movzx   ecx,word ptr [edi+54h]   ds:002b:01180054=9f59
0:000> 
eax=00000002 ebx=011804a0 ecx=00009f59 edx=00000002 esi=011804a2 edi=01180000
eip=77db801a esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x18a:
77db801a 0fb74304        movzx   eax,word ptr [ebx+4]     ds:002b:011804a4=9f5b
0:000> 
eax=00009f5b ebx=011804a0 ecx=00009f59 edx=00000002 esi=011804a2 edi=01180000
eip=77db801e esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x18e:
77db801e 33c8            xor     ecx,eax
```

&emsp;&emsp;<font size=2>此时ecx为解密后的`pre_size`，然后由此计算上一个堆块的地址是否与本堆块相同：</font></br>

```
0:000> 
eax=00009f5b ebx=011804a0 ecx=00000002 edx=00000002 esi=011804a2 edi=01180000
eip=77db8020 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x190:
77db8020 c1e103          shl     ecx,3
0:000> 
eax=00009f5b ebx=011804a0 ecx=00000010 edx=00000002 esi=011804a2 edi=01180000
eip=77db8023 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x193:
77db8023 8bf3            mov     esi,ebx
0:000> t
eax=00009f5b ebx=011804a0 ecx=00000010 edx=00000002 esi=011804a0 edi=01180000
eip=77db8025 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x195:
77db8025 2bf1            sub     esi,ecx
0:000> 
eax=00009f5b ebx=011804a0 ecx=00000010 edx=00000002 esi=01180490 edi=01180000
eip=77db8027 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x197:
77db8027 8975e0          mov     dword ptr [ebp-20h],esi ss:002b:00cffa18=00000002
0:000> 
eax=00009f5b ebx=011804a0 ecx=00000010 edx=00000002 esi=01180490 edi=01180000
eip=77db802a esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x19a:
77db802a 3bf3            cmp     esi,ebx
0:000> 
eax=00009f5b ebx=011804a0 ecx=00000010 edx=00000002 esi=01180490 edi=01180000
eip=77db802c esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000287
ntdll!RtlpFreeHeap+0x19c:
77db802c 741e            je      ntdll!RtlpFreeHeap+0x1bc (77db804c)     [br=0]
```

&emsp;&emsp;<font size=2>解密上一个堆块头：</font></br>

```
ax=00000001 ebx=011804a0 ecx=00000001 edx=00000002 esi=01180490 edi=01180000
eip=77db8037 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x1a7:
77db8037 0fb64752        movzx   eax,byte ptr [edi+52h]     ds:002b:01180052=92
0:000> 
eax=00000092 ebx=011804a0 ecx=00000001 edx=00000002 esi=01180490 edi=01180000
eip=77db803b esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x1ab:
77db803b 23c8            and     ecx,eax
0:000> 
eax=00000092 ebx=011804a0 ecx=00000000 edx=00000002 esi=01180490 edi=01180000
eip=77db803d esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x1ad:
77db803d 0fb64602        movzx   eax,byte ptr [esi+2]       ds:002b:01180492=93
0:000> 
eax=00000093 ebx=011804a0 ecx=00000000 edx=00000002 esi=01180490 edi=01180000
eip=77db8041 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x1b1:
77db8041 33c8            xor     ecx,eax
```

&emsp;&emsp;<font size=2>获取下一个堆块地址以及解密：</font></br>

```
eax=00000093 ebx=011804a0 ecx=00000001 edx=00000002 esi=01180490 edi=01180000
eip=77db804c esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x1bc:
77db804c 8d34d3          lea     esi,[ebx+edx*8]
0:000> 
eax=00000093 ebx=011804a0 ecx=00000001 edx=00000002 esi=011804b0 edi=01180000
eip=77db804f esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x1bf:
77db804f 8975d8          mov     dword ptr [ebp-28h],esi ss:002b:00cffa10=01180248
.......
.......
eax=8593b506 ebx=011804a0 ecx=00000001 edx=00000002 esi=011804b0 edi=01180000
eip=77db8060 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x1d0:
77db8060 8b4f50          mov     ecx,dword ptr [edi+50h] ds:002b:01180050=8692b504
0:000> 
eax=8593b506 ebx=011804a0 ecx=8692b504 edx=00000002 esi=011804b0 edi=01180000
eip=77db8063 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x1d3:
77db8063 33c8            xor     ecx,eax


```

&emsp;&emsp;<font size=2>检查下一个堆块的`HeapCookie`：</font></br>

```
0:000> 
eax=8593b506 ebx=011804a0 ecx=03010002 edx=00000002 esi=011804b0 edi=01180000
eip=77db8065 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x1d5:
77db8065 898d48ffffff    mov     dword ptr [ebp-0B8h],ecx ss:002b:00cff980=8593b506
0:000> 
eax=8593b506 ebx=011804a0 ecx=03010002 edx=00000002 esi=011804b0 edi=01180000
eip=77db806b esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x1db:
77db806b 8ac1            mov     al,cl
0:000> 
eax=8593b502 ebx=011804a0 ecx=03010002 edx=00000002 esi=011804b0 edi=01180000
eip=77db806d esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x1dd:
77db806d 32c5            xor     al,ch
0:000> 
eax=8593b502 ebx=011804a0 ecx=03010002 edx=00000002 esi=011804b0 edi=01180000
eip=77db806f esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x1df:
77db806f 32854affffff    xor     al,byte ptr [ebp-0B6h]     ss:002b:00cff982=01
0:000> 
eax=8593b503 ebx=011804a0 ecx=03010002 edx=00000002 esi=011804b0 edi=01180000
eip=77db8075 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x1e5:
77db8075 c1e918          shr     ecx,18h
0:000> 
eax=8593b503 ebx=011804a0 ecx=00000003 edx=00000002 esi=011804b0 edi=01180000
eip=77db8078 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x1e8:
77db8078 3ac8            cmp     cl,al
```

&emsp;&emsp;<font size=2>然后把这个被free的堆块改为空闲态，并把`UnusedBytes`置0：</font></br>

```
0:000> 
eax=00000002 ebx=011804a0 ecx=00000001 edx=00000002 esi=011804b0 edi=01180000
eip=77db829a esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
0:000> t
eax=00000002 ebx=011804a0 ecx=00000001 edx=00000002 esi=011804b0 edi=01180000
eip=77db829e esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x40e:
77db829e c6430700        mov     byte ptr [ebx+7],0         ds:002b:011804a7=0c
0:000> dt ntdll!_HEAP_ENTRY 11804a0
   +0x000 UnpackedEntry    : _HEAP_UNPACKED_ENTRY
   +0x000 Size             : 2
   +0x002 Flags            : 0 ''
   +0x003 SmallTagIndex    : 0x3 ''
   +0x000 SubSegmentCode   : 0x3000002
   +0x004 PreviousSize     : 0x9f5b
   +0x006 SegmentOffset    : 0 ''
   +0x006 LFHFlags         : 0 ''
   +0x007 UnusedBytes      : 0 ''
....
```

&emsp;&emsp;<font size=2>然后从`_HEAP`结构里取出了BlocksIndex，应该是根据堆块大小的索引排列的一个chunk map：</font></br>

```
0:000> t
eax=00000002 ebx=011804a0 ecx=011800c0 edx=00000002 esi=011804b0 edi=01180000
eip=77db82a8 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x418:
77db82a8 8b97b4000000    mov     edx,dword ptr [edi+0B4h] ds:002b:011800b4=01180248
...
    +0x0b4 BlocksIndex      : 0x01180248 Void
...
```

&emsp;&emsp;<font size=2>这个BlocksIndex的偏移0x18处存放着一个指向`_HEAP`结构体里的`FreeLists`，偏移4的地方存放着0x80，会和堆块大小对比，根据计算0x80=1kb，这应该是判断堆块是否属于`小块`的：</font></br>

```

0:000> t
eax=00000002 ebx=011804a0 ecx=011800c0 edx=01180248 esi=011804b0 edi=01180000
eip=77db82c0 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x430:
77db82c0 8b4a04          mov     ecx,dword ptr [edx+4] ds:002b:0118024c=00000080
0:000> 
eax=00000002 ebx=011804a0 ecx=00000080 edx=01180248 esi=011804b0 edi=01180000
eip=77db82c3 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x433:
77db82c3 3bc1            cmp     eax,ecx
.....
0:000> t
eax=00000002 ebx=011804a0 ecx=00000080 edx=01180248 esi=00000000 edi=01180000
eip=77db82d8 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x448:
77db82d8 8b4218          mov     eax,dword ptr [edx+18h] ds:002b:01180260=011800c0
0:000> t
eax=011800c0 ebx=011804a0 ecx=00000080 edx=01180248 esi=00000000 edi=01180000
eip=77db82db esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x44b:
77db82db 8945e0          mov     dword ptr [ebp-20h],eax ss:002b:00cffa18=01180490
...
   +0x0c0 FreeLists        : _LIST_ENTRY [ 0x1180488 - 0x11804c8 ]
...
```

&emsp;&emsp;<font size=2>然后就是`FreeLists`的操作了，我们先来看看`FreeLists`这个`_LIST_ENTRY`结构的定义：</font></br>

```
0:000> t
eax=011800c0 ebx=011804a0 ecx=00000080 edx=01180248 esi=00000000 edi=01180000
eip=77db82de esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x44e:
77db82de 8b4804          mov     ecx,dword ptr [eax+4] ds:002b:011800c4=011804c8
0:000> t
eax=011800c0 ebx=011804a0 ecx=011804c8 edx=01180248 esi=00000000 edi=01180000
eip=77db82e1 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x451:
77db82e1 3bc1            cmp     eax,ecx
0:000> dt ntdll!_LIST_ENTRY 11800c0
 [ 0x1180488 - 0x11804c8 ]
   +0x000 Flink            : 0x01180488 _LIST_ENTRY [ 0x11804c8 - 0x11800c0 ]
   +0x004 Blink            : 0x011804c8 _LIST_ENTRY [ 0x11800c0 - 0x1180488 ]
```

&emsp;&emsp;<font size=2>可以k按到`Flink`指向我们第一个释放的堆块，`Blink`指向“尾块”，或者说“TopChunk”（前者Windows叫法，后者Linux叫法）。可以看到上面有对`Blink`进行了一次比较，查看`Blink`是否指向自己（目前不清楚这个比较的含义，在没有任何一个堆块被释放的时候`Flink`和`Blink`指向尾块，尾块指向`FreeLists`）。</font></br>

&emsp;&emsp;<font size=2>然后取出了尾块头进行异或解密（无关指令省略）：</font></br>

```
0:000> 
eax=011800c0 ebx=011804a0 ecx=011804c8 edx=01180248 esi=00000000 edi=01180000
eip=77db82e9 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
ntdll!RtlpFreeHeap+0x459:
77db82e9 8d41f8          lea     eax,[ecx-8]
0:000> 
eax=011804c0 ebx=011804a0 ecx=011804c8 edx=01180248 esi=00000000 edi=01180000
eip=77db82ef esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
ntdll!RtlpFreeHeap+0x45f:
77db82ef 8b18            mov     ebx,dword ptr [eax]  ds:002b:011804c0=e392b460
0:000> 
eax=011804c0 ebx=e392b460 ecx=011804c8 edx=01180248 esi=00000000 edi=01180000
eip=77db82fc esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x46c:
77db82fc 335f50          xor     ebx,dword ptr [edi+50h] ds:002b:01180050=8692b504

```

&emsp;&emsp;<font size=2>同样进行了`HeapCookie`检查：</font></br>

```
0:000> 
eax=011804c0 ebx=65000164 ecx=011804c8 edx=01180248 esi=00000000 edi=01180000
eip=77db8305 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x475:
77db8305 8bcb            mov     ecx,ebx
0:000> 
eax=011804c0 ebx=65000164 ecx=65000164 edx=01180248 esi=00000000 edi=01180000
eip=77db8307 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x477:
77db8307 c1e910          shr     ecx,10h
0:000> 
eax=011804c0 ebx=65000164 ecx=00006500 edx=01180248 esi=00000000 edi=01180000
eip=77db830a esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x47a:
77db830a 32cf            xor     cl,bh
0:000> 
eax=011804c0 ebx=65000164 ecx=00006501 edx=01180248 esi=00000000 edi=01180000
eip=77db830c esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x47c:
77db830c 32cb            xor     cl,bl
0:000> 
eax=011804c0 ebx=65000164 ecx=00006565 edx=01180248 esi=00000000 edi=01180000
eip=77db830e esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x47e:
77db830e 8bc3            mov     eax,ebx
0:000> 
eax=65000164 ebx=65000164 ecx=00006565 edx=01180248 esi=00000000 edi=01180000
eip=77db8310 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x480:
77db8310 c1e818          shr     eax,18h
0:000> 
eax=00000065 ebx=65000164 ecx=00006565 edx=01180248 esi=00000000 edi=01180000
eip=77db8313 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x483:
77db8313 3ac1            cmp     al,cl
```

&emsp;&emsp;<font size=2>然后这里有对被释放堆块大小是否超过了尾块：</font></br>

```
eax=00000164 ebx=65000164 ecx=00000002 edx=01180248 esi=00000000 edi=01180000
eip=77db8321 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x491:
77db8321 2bc8            sub     ecx,eax
0:000> 
eax=00000164 ebx=65000164 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db8323 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
ntdll!RtlpFreeHeap+0x493:
77db8323 85c9            test    ecx,ecx
0:000> 
eax=00000164 ebx=65000164 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db8325 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x495:
77db8325 0f8f8d020000    jg      ntdll!RtlpFreeHeap+0x728 (77db85b8)     [br=0]
```

&emsp;&emsp;<font size=2>从`FreeLists`的`Flink`取出我们第一个释放的堆块，将其堆块头解密：</font></br>

```
0:000> 
eax=011800c0 ebx=65000164 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db832e esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x49e:
77db832e 8b00            mov     eax,dword ptr [eax]  ds:002b:011800c0=01180488
0:000> 
eax=01180488 ebx=65000164 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db8330 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x4a0:
77db8330 83c0f8          add     eax,0FFFFFFF8h
0:000> 
eax=01180480 ebx=65000164 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db8336 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000213
ntdll!RtlpFreeHeap+0x4a6:
77db8336 8b18            mov     ebx,dword ptr [eax]  ds:002b:01180480=8492b506
0:000> 
eax=01180480 ebx=8492b506 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db8343 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x4b3:
```

&emsp;&emsp;<font size=2>然后检查`HeapCookie`：</font></br>

```
0:000> 
eax=011800c0 ebx=65000164 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db832e esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x49e:
77db832e 8b00            mov     eax,dword ptr [eax]  ds:002b:011800c0=01180488
0:000> 
eax=01180488 ebx=65000164 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db8330 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x4a0:
77db8330 83c0f8          add     eax,0FFFFFFF8h
0:000> 
eax=01180480 ebx=65000164 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db8336 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000213
ntdll!RtlpFreeHeap+0x4a6:
77db8336 8b18            mov     ebx,dword ptr [eax]  ds:002b:01180480=8492b506
0:000> 
eax=01180480 ebx=8492b506 ecx=fffffe9e edx=01180248 esi=00000000 edi=01180000
eip=77db8343 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x4b3:
```

&emsp;&emsp;<font size=2>然后检查`FreeLists`的`Flink`是否指向最近释放的堆块（我们第一个释放的堆块）：</font></br>

```
0:000> 
eax=011804a8 ebx=011804a0 ecx=02000002 edx=01180248 esi=01180488 edi=01180000
eip=77db844a esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x5ba:
77db844a 8b4e04          mov     ecx,dword ptr [esi+4] ds:002b:0118048c=011800c0
0:000> 
eax=011804a8 ebx=011804a0 ecx=011800c0 edx=01180248 esi=01180488 edi=01180000
eip=77db844d esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x5bd:
77db844d 8b11            mov     edx,dword ptr [ecx]  ds:002b:011800c0=01180488
0:000> 
eax=011804a8 ebx=011804a0 ecx=011800c0 edx=01180488 esi=01180488 edi=01180000
eip=77db844f esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x5bf:
77db844f 3bd6            cmp     edx,esi
```

&emsp;&emsp;<font size=2>然后将我们第一个释放的堆块的地址写到我们现在正在释放的堆块的`Flink`，将`FreeLists`的地址写到`Blink`；将正在释放的堆块的地址写入`FreeLists`的`Flink`和第一个释放堆块的`Blink`：</font></br>

```
 0:000> 
eax=011804a8 ebx=011804a0 ecx=011800c0 edx=01180488 esi=01180488 edi=01180000
eip=77db8457 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x5c7:
77db8457 8930            mov     dword ptr [eax],esi  ds:002b:011804a8=00000000
0:000> 
eax=011804a8 ebx=011804a0 ecx=011800c0 edx=01180488 esi=01180488 edi=01180000
eip=77db8459 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x5c9:
77db8459 894804          mov     dword ptr [eax+4],ecx ds:002b:011804ac=00000000
0:000> 
eax=011804a8 ebx=011804a0 ecx=011800c0 edx=01180488 esi=01180488 edi=01180000
eip=77db845c esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x5cc:
77db845c 8901            mov     dword ptr [ecx],eax  ds:002b:011800c0=01180488
0:000> 
eax=011804a8 ebx=011804a0 ecx=011800c0 edx=01180488 esi=01180488 edi=01180000
eip=77db845e esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x5ce:
77db845e 894604          mov     dword ptr [esi+4],eax ds:002b:0118048c=011800c0

```

&emsp;&emsp;<font size=2>这应该就是传说中的`unlink`了吧，不过我们正在调试堆块，就先不琢磨会不会存在`unsafe unlink`的问题了，以上操作用伪代码来表示就是这样：</font></br>

```C
assert(FreeLists->Flink == PreChunk);
ChunkNow->Flink = PreChunk;
ChunkNow->Blink = FreeLists;
FreeList->Flink = ChunkNow;
PreChunk->Blink = ChunkNow;
```

&emsp;&emsp;<font size=2>也就是我们上面放过的单链表堆块链接图：</font></br>

![单堆链](https://raw.githubusercontent.com/fangdada/ctf/master/how2pwn/Windows/RtlpHeapFree/SmallEmptyList/screenshot/单堆链.png)

&emsp;&emsp;<font size=2>然后把当前释放的堆块的大小加到`_HEAP`里的`TotalFreeSize`里：</font></br>

```
0:000> 
eax=00000002 ebx=011804a0 ecx=011800c0 edx=01180488 esi=01180488 edi=01180000
eip=77db8464 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x5d4:
77db8464 014774          add     dword ptr [edi+74h],eax ds:002b:01180074=00000166
```

&emsp;&emsp;<font size=2>然后从`BlocksIndex`偏移0x20处取出一张表，将刚释放的堆块以大小为索引放入这张表里，猜测这张表就是传说中的空闲双向链表：</font></br>

```
0:000> 
eax=00000002 ebx=011804a0 ecx=01180248 edx=00000002 esi=01180488 edi=01180000
eip=77db84cf esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x63f:
77db84cf 8b4120          mov     eax,dword ptr [ecx+20h] ds:002b:01180268=0118027c
0:000> 
eax=0118027c ebx=011804a0 ecx=011804a8 edx=00000002 esi=00000002 edi=01180000
eip=77db84d8 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x648:
77db84d8 890cb0          mov     dword ptr [eax+esi*4],ecx ds:002b:01180284=01180488
```

&emsp;&emsp;<font size=2>每次对堆块的访问几乎都会把头解密一次然后异或检查`HeapCookie`，接下来就不说这一点了，否则篇幅会比较冗长。但这里将我们刚刚释放的堆块拿出来异或生成的`HeapCookie`放到了`SmallTagIndex`，就像是重新生成了Cookie一样：</font></br>

```
eax=0118027c ebx=011804a0 ecx=011804a8 edx=00000002 esi=01180488 edi=01180000
eip=77db8506 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x676:
77db8506 0fb64b02        movzx   ecx,byte ptr [ebx+2]       ds:002b:011804a2=00
0:000> 
eax=0118027c ebx=011804a0 ecx=00000000 edx=00000002 esi=01180488 edi=01180000
eip=77db850a esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x67a:
77db850a 0fb64301        movzx   eax,byte ptr [ebx+1]       ds:002b:011804a1=00
0:000> 
eax=00000000 ebx=011804a0 ecx=00000000 edx=00000002 esi=01180488 edi=01180000
eip=77db850e esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x67e:
77db850e 33c8            xor     ecx,eax
0:000> 
eax=00000000 ebx=011804a0 ecx=00000000 edx=00000002 esi=01180488 edi=01180000
eip=77db8510 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x680:
77db8510 0fb603          movzx   eax,byte ptr [ebx]         ds:002b:011804a0=02
0:000> 
eax=00000002 ebx=011804a0 ecx=00000000 edx=00000002 esi=01180488 edi=01180000
eip=77db8513 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x683:
77db8513 33c8            xor     ecx,eax
0:000> 
eax=00000002 ebx=011804a0 ecx=00000002 edx=00000002 esi=01180488 edi=01180000
eip=77db8515 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x685:
77db8515 884b03          mov     byte ptr [ebx+3],cl        ds:002b:011804a3=03
0:000> 
eax=00000002 ebx=011804a0 ecx=00000002 edx=00000002 esi=01180488 edi=01180000
eip=77db8518 esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x688:
77db8518 8b4750          mov     eax,dword ptr [edi+50h] ds:002b:01180050=8692b504
0:000> t
eax=8692b504 ebx=011804a0 ecx=00000002 edx=00000002 esi=01180488 edi=01180000
eip=77db851b esp=00cff940 ebp=00cffa38 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x68b:
77db851b 3103            xor     dword ptr [ebx],eax  ds:002b:011804a0=02000002
8 8b4750          mov     eax,dword ptr [edi+50h] ds:002b:01180050=8692b504
```

&emsp;&emsp;<font size=2>猜测是因为遇到和相邻空闲堆块unlink完毕后需要重新更新`HeapCookie`，完了之后重新把堆块头加密了。然后控制流就返回了：</font></br>

```
0:000> 
eax=00000001 ebx=011804a8 ecx=64802a23 edx=00000002 esi=011804a0 edi=01180000
eip=77db854c esp=00cffa38 ebp=00cffa38 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x6bc:
77db854c 5d              pop     ebp
0:000> 
eax=00000001 ebx=011804a8 ecx=64802a23 edx=00000002 esi=011804a0 edi=01180000
eip=77db854d esp=00cffa3c ebp=00cffa60 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x6bd:
77db854d c20800          ret     8
```

&emsp;&emsp;<font size=2>第一次对Windows的最简单的一次Free分析操作就完成了，也算是一篇开山吧，后续就会用更复杂的场景来分析出跟目前这种不一样的情况，毕竟单一场景不可能知道Free的全部细节。时间还长，下一篇见！</font></br>