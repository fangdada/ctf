### Windows10 1903 x86 对堆块unsafe-unlink利用失败的探索

> 环境：Windows10 1903
>
> 编译选项：Release x86
>
> 调试器：Windbg

&emsp;&emsp;<font size=2>首先我们先熟悉一下Windows下的unlink做了哪些工作（**注：windbg记录基址可能不同，只需要看偏移就行了**）：</font></br>

```C
#include <windows.h>
#include <stdio.h>

int main()
{
    PVOID p0,p1,p2,p3,p4,p5,p6,p7,p8;
    HANDLE hp=HeapCreate(HEAP_NO_SERIALIZE,0x1000,0x10000);

    p1=HeapAlloc(hp,HEAP_ZERO_MEMORY,3);
    p2=HeapAlloc(hp,HEAP_ZERO_MEMORY,3);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,4);
    HeapAlloc(hp,HEAP_ZERO_MEMORY,4);


    HeapFree(hp,HEAP_NO_SERIALIZE,p1);
    __asm int 3

    HeapFree(hp,HEAP_NO_SERIALIZE,p2);

    return 0;
}
```
&emsp;&emsp;<font size=2>然后直接用windbg打开attach上去，往下跟踪到`RtlpHeapFree`。接下来就是解密`_HEAP_ENTRY`和检查HeapCookie：</font></br>
```
0:000> 
eax=7ffe0380 ebx=00000003 ecx=00860000 edx=00000003 esi=008604a0 edi=00860000
eip=77a5df03 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x293:
77a5df03 8b4750          mov     eax,dword ptr [edi+50h] ds:002b:00860050=3efbed75
0:000> 
eax=3efbed75 ebx=00000003 ecx=00860000 edx=00000003 esi=008604a0 edi=00860000
eip=77a5df06 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x296:
77a5df06 3106            xor     dword ptr [esi],eax  ds:002b:008604a0=3dfaed77
0:000> 
eax=3efbed75 ebx=00000003 ecx=00860000 edx=00000003 esi=008604a0 edi=00860000
eip=77a5df08 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x298:
77a5df08 8a4602          mov     al,byte ptr [esi+2]        ds:002b:008604a2=01
0:000> 
eax=3efbed01 ebx=00000003 ecx=00860000 edx=00000003 esi=008604a0 edi=00860000
eip=77a5df0b esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x29b:
77a5df0b 324601          xor     al,byte ptr [esi+1]        ds:002b:008604a1=00
0:000> 
eax=3efbed01 ebx=00000003 ecx=00860000 edx=00000003 esi=008604a0 edi=00860000
eip=77a5df0e esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x29e:
77a5df0e 3206            xor     al,byte ptr [esi]          ds:002b:008604a0=02
0:000> 
eax=3efbed03 ebx=00000003 ecx=00860000 edx=00000003 esi=008604a0 edi=00860000
eip=77a5df10 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x2a0:
77a5df10 384603          cmp     byte ptr [esi+3],al        ds:002b:008604a3=03
```
&emsp;&emsp;<font size=2>然后解密`_HEAP_ENTRY`的`PreviousSize`，获取上一个堆块，比较是否为自身：</font></br>
```
0:000> 
eax=00000002 ebx=008604a2 ecx=0000fb5e edx=00000002 esi=008604a0 edi=00860000
eip=77a5dfed esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x37d:
77a5dfed 0fb74604        movzx   eax,word ptr [esi+4]     ds:002b:008604a4=fb5c
0:000> 
eax=0000fb5c ebx=008604a2 ecx=0000fb5e edx=00000002 esi=008604a0 edi=00860000
eip=77a5dff1 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x381:
77a5dff1 33c8            xor     ecx,eax
0:000> 
eax=0000fb5c ebx=008604a2 ecx=00000002 edx=00000002 esi=008604a0 edi=00860000
eip=77a5dff3 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x383:
77a5dff3 c1e103          shl     ecx,3
0:000> 
eax=0000fb5c ebx=008604a2 ecx=00000010 edx=00000002 esi=008604a0 edi=00860000
eip=77a5dff6 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x386:
77a5dff6 8bde            mov     ebx,esi
0:000> 
eax=0000fb5c ebx=008604a0 ecx=00000010 edx=00000002 esi=008604a0 edi=00860000
eip=77a5dff8 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x388:
77a5dff8 2bd9            sub     ebx,ecx
0:000> t
eax=0000fb5c ebx=00860490 ecx=00000010 edx=00000002 esi=008604a0 edi=00860000
eip=77a5dffa esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x38a:
77a5dffa 3bde            cmp     ebx,esi

```
&emsp;&emsp;<font size=2>检查上一个堆块是否为占用态：</font></br>
```
0:000> t
eax=0000fb5c ebx=00860490 ecx=00000010 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e002 esp=009cf768 ebp=009cf830 iopl=0         nv up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000287
ntdll!RtlpFreeHeap+0x392:
77a5e002 8b4f4c          mov     ecx,dword ptr [edi+4Ch] ds:002b:0086004c=00100000
0:000> 
eax=0000fb5c ebx=00860490 ecx=00100000 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e005 esp=009cf768 ebp=009cf830 iopl=0         nv up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000287
ntdll!RtlpFreeHeap+0x395:
77a5e005 8bc1            mov     eax,ecx
0:000> 
eax=00100000 ebx=00860490 ecx=00100000 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e007 esp=009cf768 ebp=009cf830 iopl=0         nv up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000287
ntdll!RtlpFreeHeap+0x397:
77a5e007 c1e814          shr     eax,14h
0:000> 
eax=00000001 ebx=00860490 ecx=00100000 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e00a esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x39a:
77a5e00a 224752          and     al,byte ptr [edi+52h]      ds:002b:00860052=fb
0:000> 
eax=00000001 ebx=00860490 ecx=00100000 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e00d esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x39d:
77a5e00d 324302          xor     al,byte ptr [ebx+2]        ds:002b:00860492=fb
0:000> 
eax=000000fa ebx=00860490 ecx=00100000 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e010 esp=009cf768 ebp=009cf830 iopl=0         nv up ei ng nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000286
ntdll!RtlpFreeHeap+0x3a0:
77a5e010 a801            test    al,1
```
&emsp;&emsp;<font size=2>解密上一个堆块的堆块头：</font></br>
```
0:000> 
eax=000000fa ebx=00860490 ecx=00100000 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e01c esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x3ac:
77a5e01c 8b5750          mov     edx,dword ptr [edi+50h] ds:002b:00860050=3efbed75
0:000> 
eax=000000fa ebx=00860490 ecx=00100000 edx=3efbed75 esi=008604a0 edi=00860000
eip=77a5e01f esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x3af:
77a5e01f 3313            xor     edx,dword ptr [ebx]  ds:002b:00860490=3cfbed77
0:000> 
eax=000000fa ebx=00860490 ecx=00100000 edx=02000002 esi=008604a0 edi=00860000
eip=77a5e021 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x3b1:
77a5e021 8913            mov     dword ptr [ebx],edx  ds:002b:00860490=3cfbed77
```
&emsp;&emsp;<font size=2>然后检查`HeapCookie`：</font></br>
```
0:000> 
eax=000000fa ebx=00860490 ecx=00100000 edx=02000002 esi=008604a0 edi=00860000
eip=77a5e023 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x3b3:
77a5e023 8bca            mov     ecx,edx
0:000> 
eax=000000fa ebx=00860490 ecx=02000002 edx=02000002 esi=008604a0 edi=00860000
eip=77a5e025 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x3b5:
77a5e025 c1e910          shr     ecx,10h
0:000> 
eax=000000fa ebx=00860490 ecx=00000200 edx=02000002 esi=008604a0 edi=00860000
eip=77a5e028 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x3b8:
77a5e028 8bc2            mov     eax,edx
0:000> 
eax=02000002 ebx=00860490 ecx=00000200 edx=02000002 esi=008604a0 edi=00860000
eip=77a5e02a esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x3ba:
77a5e02a c1e808          shr     eax,8
0:000> 
eax=00020000 ebx=00860490 ecx=00000200 edx=02000002 esi=008604a0 edi=00860000
eip=77a5e02d esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x3bd:
77a5e02d 32c8            xor     cl,al
0:000> 
eax=00020000 ebx=00860490 ecx=00000200 edx=02000002 esi=008604a0 edi=00860000
eip=77a5e02f esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3bf:
77a5e02f 32ca            xor     cl,dl
0:000> 
eax=00020000 ebx=00860490 ecx=00000202 edx=02000002 esi=008604a0 edi=00860000
eip=77a5e031 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x3c1:
77a5e031 c1ea18          shr     edx,18h
0:000> 
eax=00020000 ebx=00860490 ecx=00000202 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e034 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x3c4:
77a5e034 3ad1            cmp     dl,cl
```
&emsp;&emsp;<font size=2>然后检查了堆块`Flink`和`Blink`的合法性:</font></br>
```
0:000> 
eax=00020000 ebx=00860490 ecx=00000202 edx=00000002 esi=008604a0 edi=00860000
eip=77a5e042 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3d2:
77a5e042 8d5308          lea     edx,[ebx+8]
0:000> 
eax=00020000 ebx=00860490 ecx=00000202 edx=00860498 esi=008604a0 edi=00860000
eip=77a5e045 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3d5:
77a5e045 8b0a            mov     ecx,dword ptr [edx]  ds:002b:00860498=008604d8
0:000> 
eax=00020000 ebx=00860490 ecx=008604d8 edx=00860498 esi=008604a0 edi=00860000
eip=77a5e047 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3d7:
77a5e047 894dd4          mov     dword ptr [ebp-2Ch],ecx ss:002b:009cf804=00000000
0:000> 
eax=00020000 ebx=00860490 ecx=008604d8 edx=00860498 esi=008604a0 edi=00860000
eip=77a5e04a esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3da:
77a5e04a 8b430c          mov     eax,dword ptr [ebx+0Ch] ds:002b:0086049c=008600c0
0:000> 
eax=008600c0 ebx=00860490 ecx=008604d8 edx=00860498 esi=008604a0 edi=00860000
eip=77a5e04d esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3dd:
77a5e04d 8945bc          mov     dword ptr [ebp-44h],eax ss:002b:009cf7ec=00000000
0:000> 
eax=008600c0 ebx=00860490 ecx=008604d8 edx=00860498 esi=008604a0 edi=00860000
eip=77a5e050 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3e0:
77a5e050 8b00            mov     eax,dword ptr [eax]  ds:002b:008600c0=00860498
0:000> 
eax=00860498 ebx=00860490 ecx=008604d8 edx=00860498 esi=008604a0 edi=00860000
eip=77a5e052 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3e2:
77a5e052 8b4904          mov     ecx,dword ptr [ecx+4] ds:002b:008604dc=00860498
0:000> 
eax=00860498 ebx=00860490 ecx=00860498 edx=00860498 esi=008604a0 edi=00860000
eip=77a5e055 esp=009cf768 ebp=009cf830 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3e5:
77a5e055 3bc1            cmp     eax,ecx
```
&emsp;&emsp;<font size=2>相当于如下伪代码检查：</font></br>
```C
assert(PreChunk->Flink->Blink == PreChunk->Blink->Flink == PreChunk)
```
&emsp;&emsp;<font size=2>检查了上一个空闲态的堆块是否为`SmallChunk`：</font></br>
```
0:000> 
eax=00000002 ebx=007a0490 ecx=007a0498 edx=007a0258 esi=007a04a0 edi=007a0000
eip=77a5e075 esp=003dfae0 ebp=003dfba8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x405:
77a5e075 0fb703          movzx   eax,word ptr [ebx]       ds:002b:007a0490=0002
0:000> 
eax=00000002 ebx=007a0490 ecx=007a0498 edx=007a0258 esi=007a04a0 edi=007a0000
eip=77a5e078 esp=003dfae0 ebp=003dfba8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x408:
77a5e078 8b4a04          mov     ecx,dword ptr [edx+4] ds:002b:007a025c=00000080
0:000> 
eax=00000002 ebx=007a0490 ecx=00000080 edx=007a0258 esi=007a04a0 edi=007a0000
eip=77a5e07b esp=003dfae0 ebp=003dfba8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x40b:
77a5e07b 3bc1            cmp     eax,ecx
```
&emsp;&emsp;<font size=2>然后调用了`RtlpHeapRemoveListEntry`进行空表（`EmtryList`)的链表更新，我们步入分析：</font></br>
```
0:000> 
eax=00860498 ebx=00860490 ecx=00860000 edx=00860258 esi=008604a0 edi=00860000
eip=77a5e098 esp=009cf758 ebp=009cf830 iopl=0         nv up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000287
ntdll!RtlpFreeHeap+0x428:
77a5e098 e8b3420000      call    ntdll!RtlpHeapRemoveListEntry (77a62350)
```
&emsp;&emsp;<font size=2>从`_HEAP`结构的0xb4偏移处取出`BlocksIndex`结构，然后根据上一个空闲块的size索引从`EmptyList`取出上一个空闲块:</font></br>
```
0:000> 
eax=007a0498 ebx=007a0490 ecx=007a0000 edx=00000002 esi=00000002 edi=007a0258
eip=77a62375 esp=003dfaa8 ebp=003dfac8 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapRemoveListEntry+0x25:
77a62375 8b4720          mov     eax,dword ptr [edi+20h] ds:002b:007a0278=007a028c
0:000> 
eax=007a028c ebx=007a0490 ecx=007a0000 edx=00000002 esi=00000002 edi=007a0258
eip=77a62378 esp=003dfaa8 ebp=003dfac8 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapRemoveListEntry+0x28:
77a62378 8b1c90          mov     ebx,dword ptr [eax+edx*4] ds:002b:007a0294=007a0498
```
&emsp;&emsp;<font size=2>检查以我们释放堆块的`PreviousSize`计算得到的上一个空闲块与`EmptyList`取出的堆块是否相同：</font></br>
```
0:000> t
eax=007a028c ebx=007a0498 ecx=007a0000 edx=00000002 esi=00000002 edi=007a0258
eip=77a6237e esp=003dfaa8 ebp=003dfac8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapRemoveListEntry+0x2e:
77a6237e 895df0          mov     dword ptr [ebp-10h],ebx ss:002b:003dfab8=00000000
...........
0:000> 
eax=007a028c ebx=0000007f ecx=007a0000 edx=00000002 esi=00000002 edi=007a0258
eip=77a62390 esp=003dfaa8 ebp=003dfac8 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
ntdll!RtlpHeapRemoveListEntry+0x40:
77a62390 8b5d0c          mov     ebx,dword ptr [ebp+0Ch] ss:002b:003dfad4=007a0498
0:000> 
eax=007a028c ebx=007a0498 ecx=007a0000 edx=00000002 esi=00000002 edi=007a0258
eip=77a62393 esp=003dfaa8 ebp=003dfac8 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
ntdll!RtlpHeapRemoveListEntry+0x43:
77a62393 395df0          cmp     dword ptr [ebp-10h],ebx ss:002b:003dfab8=007a0498
```
&emsp;&emsp;<font size=2>检查第一个堆块的`Flink`指向的堆块是否指向`FreeList`（事实上`FreeList`与我们释放的堆块和尾块一起形成了循环双向链表)：</font></br>
```
0:000> 
eax=0086028c ebx=0000007f ecx=00860000 edx=00000002 esi=00000002 edi=00860258
eip=77a62390 esp=009cf730 ebp=009cf750 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
ntdll!RtlpHeapRemoveListEntry+0x40:
77a62390 8b5d0c          mov     ebx,dword ptr [ebp+0Ch] ss:002b:009cf75c=00860498
...........
0:000> 
eax=0086028c ebx=00860498 ecx=0000007f edx=00000002 esi=00000002 edi=00860258
eip=77a623ac esp=009cf730 ebp=009cf750 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
ntdll!RtlpHeapRemoveListEntry+0x5c:
77a623ac 8b1b            mov     ebx,dword ptr [ebx]  ds:002b:00860498=008604d8
...........
0:000> 
eax=0086028c ebx=008604d8 ecx=00860000 edx=00000002 esi=00000002 edi=00860258
eip=77a623b3 esp=009cf730 ebp=009cf750 iopl=0         nv up ei ng nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000293
ntdll!RtlpHeapRemoveListEntry+0x63:
77a623b3 3b5f18          cmp     ebx,dword ptr [edi+18h] ds:002b:00860270=008600c0
```
&emsp;&emsp;<font size=2>随后对其进行解密与`HeapCookie`校验:</font></br>
```
0:000> 
eax=5dfbec17 ebx=008604d8 ecx=00860000 edx=00000002 esi=00000002 edi=00860258
eip=77a623f5 esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapRemoveListEntry+0xa5:
77a623f5 334150          xor     eax,dword ptr [ecx+50h] ds:002b:00860050=3efbed75
0:000> 
eax=63000162 ebx=008604d8 ecx=00860000 edx=00000002 esi=00000002 edi=00860258
eip=77a623f8 esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapRemoveListEntry+0xa8:
77a623f8 8bc8            mov     ecx,eax
0:000> 
eax=63000162 ebx=008604d8 ecx=63000162 edx=00000002 esi=00000002 edi=00860258
eip=77a623fa esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapRemoveListEntry+0xaa:
77a623fa 8945f8          mov     dword ptr [ebp-8],eax ss:002b:009cf748=0000007f
0:000> 
eax=63000162 ebx=008604d8 ecx=63000162 edx=00000002 esi=00000002 edi=00860258
eip=77a623fd esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapRemoveListEntry+0xad:
77a623fd c1e808          shr     eax,8
0:000> 
eax=00630001 ebx=008604d8 ecx=63000162 edx=00000002 esi=00000002 edi=00860258
eip=77a62400 esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapRemoveListEntry+0xb0:
77a62400 c1e910          shr     ecx,10h
0:000> 
eax=00630001 ebx=008604d8 ecx=00006300 edx=00000002 esi=00000002 edi=00860258
eip=77a62403 esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapRemoveListEntry+0xb3:
77a62403 32c8            xor     cl,al
0:000> 
eax=00630001 ebx=008604d8 ecx=00006301 edx=00000002 esi=00000002 edi=00860258
eip=77a62405 esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapRemoveListEntry+0xb5:
77a62405 8b45f8          mov     eax,dword ptr [ebp-8] ss:002b:009cf748=63000162
0:000> 
eax=63000162 ebx=008604d8 ecx=00006301 edx=00000002 esi=00000002 edi=00860258
eip=77a62408 esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapRemoveListEntry+0xb8:
77a62408 32c8            xor     cl,al
0:000> 
eax=63000162 ebx=008604d8 ecx=00006363 edx=00000002 esi=00000002 edi=00860258
eip=77a6240a esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapRemoveListEntry+0xba:
77a6240a c1e818          shr     eax,18h
0:000> 
eax=00000063 ebx=008604d8 ecx=00006363 edx=00000002 esi=00000002 edi=00860258
eip=77a6240d esp=009cf730 ebp=009cf750 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapRemoveListEntry+0xbd:
77a6240d 3ac1            cmp     al,cl
```
&emsp;&emsp;<font size=2>置零`EmptyList`中上一个堆块的记录：</font></br>
```
0:000> 
eax=00000162 ebx=013a04d8 ecx=fffffea0 edx=00000002 esi=00000002 edi=013a0258
eip=77a623b8 esp=010ff658 ebp=010ff678 iopl=0         nv up ei ng nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000286
ntdll!RtlpHeapRemoveListEntry+0x68:
77a623b8 8b4720          mov     eax,dword ptr [edi+20h] ds:002b:013a0278=013a028c
0:000> 
eax=013a028c ebx=013a04d8 ecx=fffffea0 edx=00000002 esi=00000002 edi=013a0258
eip=77a623bb esp=010ff658 ebp=010ff678 iopl=0         nv up ei ng nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000286
ntdll!RtlpHeapRemoveListEntry+0x6b:
77a623bb 83249000        and     dword ptr [eax+edx*4],0 ds:002b:013a0294=013a0498
```
&emsp;&emsp;<font size=2>然后从`BlocksIndex`的偏移0x1C处取出的一个类似`SizeMap`的表，将之置零，这张表以1k大小的粒度作为索引，存放着最近释放的堆块的大小:</font></br>
```
0:000> t
eax=013a028c ebx=013a04d8 ecx=fffffea0 edx=00000002 esi=00000002 edi=013a0258
eip=77a623c1 esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapRemoveListEntry+0x71:
77a623c1 8b4f1c          mov     ecx,dword ptr [edi+1Ch] ds:002b:013a0274=013a027c
0:000> 
eax=013a028c ebx=013a04d8 ecx=013a027c edx=00000002 esi=00000002 edi=013a0258
eip=77a623c4 esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapRemoveListEntry+0x74:
77a623c4 83e61f          and     esi,1Fh
0:000> 
eax=013a028c ebx=013a04d8 ecx=013a027c edx=00000002 esi=00000002 edi=013a0258
eip=77a623c7 esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapRemoveListEntry+0x77:
77a623c7 c1ea05          shr     edx,5
0:000> 
eax=013a028c ebx=013a04d8 ecx=013a027c edx=00000000 esi=00000002 edi=013a0258
eip=77a623ca esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapRemoveListEntry+0x7a:
77a623ca 8b0491          mov     eax,dword ptr [ecx+edx*4] ds:002b:013a027c=00000004
0:000> 
eax=00000004 ebx=013a04d8 ecx=013a027c edx=00000000 esi=00000002 edi=013a0258
eip=77a623cd esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapRemoveListEntry+0x7d:
77a623cd 0fb3f0          btr     eax,esi
0:000> 
eax=00000000 ebx=013a04d8 ecx=013a027c edx=00000000 esi=00000002 edi=013a0258
eip=77a623d0 esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
ntdll!RtlpHeapRemoveListEntry+0x80:
77a623d0 890491          mov     dword ptr [ecx+edx*4],eax ds:002b:013a027c=00000004
```
&emsp;&emsp;<font size=2>然后进行如下unlink操作将新堆块脱链：</font></br>
```
0:000> 
eax=00020000 ebx=013a0490 ecx=00000202 edx=00000002 esi=013a04a0 edi=013a0000
eip=77a5e042 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3d2:
77a5e042 8d5308          lea     edx,[ebx+8]
0:000> 
eax=00020000 ebx=013a0490 ecx=00000202 edx=013a0498 esi=013a04a0 edi=013a0000
eip=77a5e045 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3d5:
77a5e045 8b0a            mov     ecx,dword ptr [edx]  ds:002b:013a0498=013a04d8
0:000> 
eax=00020000 ebx=013a0490 ecx=013a04d8 edx=013a0498 esi=013a04a0 edi=013a0000
eip=77a5e047 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3d7:
77a5e047 894dd4          mov     dword ptr [ebp-2Ch],ecx ss:002b:010ff72c=00000000
0:000> 
eax=00020000 ebx=013a0490 ecx=013a04d8 edx=013a0498 esi=013a04a0 edi=013a0000
eip=77a5e04a esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3da:
77a5e04a 8b430c          mov     eax,dword ptr [ebx+0Ch] ds:002b:013a049c=013a00c0
0:000> 
eax=013a00c0 ebx=013a0490 ecx=013a04d8 edx=013a0498 esi=013a04a0 edi=013a0000
eip=77a5e04d esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x3dd:
77a5e04d 8945bc          mov     dword ptr [ebp-44h],eax ss:002b:010ff714=00000000
......................
0:000> 
eax=00000000 ebx=013a0490 ecx=013a027c edx=00000000 esi=013a04a0 edi=013a0000
eip=77a5e09d esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
ntdll!RtlpFreeHeap+0x42d:
77a5e09d 8b45d4          mov     eax,dword ptr [ebp-2Ch] ss:002b:010ff72c=013a04d8
0:000> 
eax=013a04d8 ebx=013a0490 ecx=013a027c edx=00000000 esi=013a04a0 edi=013a0000
eip=77a5e0a0 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
ntdll!RtlpFreeHeap+0x430:
77a5e0a0 8b4dbc          mov     ecx,dword ptr [ebp-44h] ss:002b:010ff714=013a00c0
0:000> 
eax=013a04d8 ebx=013a0490 ecx=013a00c0 edx=00000000 esi=013a04a0 edi=013a0000
eip=77a5e0a3 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
ntdll!RtlpFreeHeap+0x433:
77a5e0a3 8901            mov     dword ptr [ecx],eax  ds:002b:013a00c0=013a0498
0:000> 
eax=013a04d8 ebx=013a0490 ecx=013a00c0 edx=00000000 esi=013a04a0 edi=013a0000
eip=77a5e0a5 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
ntdll!RtlpFreeHeap+0x435:
77a5e0a5 894804          mov     dword ptr [eax+4],ecx ds:002b:013a04dc=013a0498
```
&emsp;&emsp;<font size=2>用伪代码来表示如下：</font></br>
```C
PreChunk->Flink->Blink=PreChunk->Blink->Flink;
//此时PreChunk->Flink为尾块，PreChunk->Blink为FreeList
```
&emsp;&emsp;<font size=2>然后修改这个空闲块的大小，标志位和下一个堆块的`PreviousSize`：</font></br>
```
0:000> 
eax=013a04d8 ebx=013a0490 ecx=013a0000 edx=00000000 esi=013a04a0 edi=013a0000
eip=77a5e184 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x514:
77a5e184 c6430200        mov     byte ptr [ebx+2],0         ds:002b:013a0492=00
0:000> t
eax=013a04d8 ebx=013a0490 ecx=013a0000 edx=00000000 esi=013a04a0 edi=013a0000
eip=77a5e188 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x518:
77a5e188 c6430700        mov     byte ptr [ebx+7],0         ds:002b:013a0497=00
.......
0:000> 
eax=013a04d8 ebx=013a0490 ecx=013a0000 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e191 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x521:
77a5e191 0fb703          movzx   eax,word ptr [ebx]       ds:002b:013a0490=0002
0:000> 
eax=00000002 ebx=013a0490 ecx=013a0000 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e194 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x524:
77a5e194 8b4de0          mov     ecx,dword ptr [ebp-20h] ss:002b:010ff738=00000002
0:000> 
eax=00000002 ebx=013a0490 ecx=00000002 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e197 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x527:
77a5e197 03c8            add     ecx,eax
0:000> 
eax=00000002 ebx=013a0490 ecx=00000004 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e199 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x529:
77a5e199 894de0          mov     dword ptr [ebp-20h],ecx ss:002b:010ff738=00000002
0:000> 
eax=00000002 ebx=013a0490 ecx=00000004 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e19c esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x52c:
77a5e19c 66890b          mov     word ptr [ebx],cx        ds:002b:013a0490=0002
0:000> t
eax=00000002 ebx=013a0490 ecx=00000004 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e19f esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x52f:
77a5e19f 8b4de0          mov     ecx,dword ptr [ebp-20h] ss:002b:010ff738=00000004
0:000> 
eax=00000002 ebx=013a0490 ecx=00000004 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e1a2 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x532:
77a5e1a2 668b4754        mov     ax,word ptr [edi+54h]    ds:002b:013a0054=e542
0:000> 
eax=0000e542 ebx=013a0490 ecx=00000004 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e1a6 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x536:
77a5e1a6 6633c1          xor     ax,cx
0:000> 
eax=0000e546 ebx=013a0490 ecx=00000004 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e1a9 esp=010ff690 ebp=010ff758 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x539:
77a5e1a9 668944cb04      mov     word ptr [ebx+ecx*8+4],ax ds:002b:013a04b4=e540
```
&emsp;&emsp;<font size=2>用新空闲块（虽然这个堆块还没被链入空闲循环双链表)的大小计算到下一个堆块，解密下一个堆块的堆块头和校验`HeapCookie`：</font></br>
```
0:000> 
eax=0000e546 ebx=013a0490 ecx=00000004 edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e1c1 esp=010ff690 ebp=010ff758 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x551:
77a5e1c1 8b55e0          mov     edx,dword ptr [ebp-20h] ss:002b:010ff738=00000004
0:000> 
eax=0000e546 ebx=013a0490 ecx=00000004 edx=00000004 esi=013a0490 edi=013a0000
eip=77a5e1c4 esp=010ff690 ebp=010ff758 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x554:
77a5e1c4 8d1cd6          lea     ebx,[esi+edx*8]
.......
0:000> 
eax=0000e546 ebx=013a04b0 ecx=00000004 edx=00000004 esi=013a0490 edi=013a0000
eip=77a5e1d0 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x560:
77a5e1d0 8b03            mov     eax,dword ptr [ebx]  ds:002b:013a04b0=10be6cf9
0:000> 
eax=10be6cf9 ebx=013a04b0 ecx=00000004 edx=00000004 esi=013a0490 edi=013a0000
eip=77a5e1d2 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x562:
77a5e1d2 898548ffffff    mov     dword ptr [ebp-0B8h],eax ss:002b:010ff6a0=00000000
0:000> 
eax=10be6cf9 ebx=013a04b0 ecx=00000004 edx=00000004 esi=013a0490 edi=013a0000
eip=77a5e1d8 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x568:
77a5e1d8 8b5750          mov     edx,dword ptr [edi+50h] ds:002b:013a0050=13bf6cfb
0:000> 
eax=10be6cf9 ebx=013a04b0 ecx=00000004 edx=13bf6cfb esi=013a0490 edi=013a0000
eip=77a5e1db esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x56b:
77a5e1db 33d0            xor     edx,eax
0:000> 
eax=10be6cf9 ebx=013a04b0 ecx=00000004 edx=03010002 esi=013a0490 edi=013a0000
eip=77a5e1dd esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x56d:
77a5e1dd 899548ffffff    mov     dword ptr [ebp-0B8h],edx ss:002b:010ff6a0=10be6cf9
0:000> t
eax=10be6cf9 ebx=013a04b0 ecx=00000004 edx=03010002 esi=013a0490 edi=013a0000
eip=77a5e1e3 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x573:
77a5e1e3 8bca            mov     ecx,edx
0:000> 
eax=10be6cf9 ebx=013a04b0 ecx=03010002 edx=03010002 esi=013a0490 edi=013a0000
eip=77a5e1e5 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x575:
77a5e1e5 c1e910          shr     ecx,10h
0:000> 
eax=10be6cf9 ebx=013a04b0 ecx=00000301 edx=03010002 esi=013a0490 edi=013a0000
eip=77a5e1e8 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x578:
77a5e1e8 8bc2            mov     eax,edx
0:000> 
eax=03010002 ebx=013a04b0 ecx=00000301 edx=03010002 esi=013a0490 edi=013a0000
eip=77a5e1ea esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x57a:
77a5e1ea c1e808          shr     eax,8
0:000> 
eax=00030100 ebx=013a04b0 ecx=00000301 edx=03010002 esi=013a0490 edi=013a0000
eip=77a5e1ed esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x57d:
77a5e1ed 32c8            xor     cl,al
0:000> 
eax=00030100 ebx=013a04b0 ecx=00000301 edx=03010002 esi=013a0490 edi=013a0000
eip=77a5e1ef esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x57f:
77a5e1ef 32ca            xor     cl,dl
0:000> 
eax=00030100 ebx=013a04b0 ecx=00000303 edx=03010002 esi=013a0490 edi=013a0000
eip=77a5e1f1 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x581:
77a5e1f1 c1ea18          shr     edx,18h
0:000> 
eax=00030100 ebx=013a04b0 ecx=00000303 edx=00000003 esi=013a0490 edi=013a0000
eip=77a5e1f4 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0x584:
77a5e1f4 3ad1            cmp     dl,cl
```
&emsp;&emsp;<font size=2>检查其是否为占用态:</font></br>
```
0:000> 
eax=00000001 ebx=013a04b0 ecx=00100000 edx=00000004 esi=013a0490 edi=013a0000
eip=77a5e228 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x5b8:
77a5e228 224752          and     al,byte ptr [edi+52h]      ds:002b:013a0052=bf
0:000> 
eax=00000001 ebx=013a04b0 ecx=00100000 edx=00000004 esi=013a0490 edi=013a0000
eip=77a5e22b esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0x5bb:
77a5e22b 324302          xor     al,byte ptr [ebx+2]        ds:002b:013a04b2=be
0:000> 
eax=000000bf ebx=013a04b0 ecx=00100000 edx=00000004 esi=013a0490 edi=013a0000
eip=77a5e22e esp=010ff690 ebp=010ff758 iopl=0         nv up ei ng nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000282
ntdll!RtlpFreeHeap+0x5be:
77a5e22e a801            test    al,1
```
&emsp;&emsp;<font size=2>然后从`BlocksIndex`的偏移0x18处取出`FreeLists`，检查其`Flink`和`Blink`指向的堆块的头部是否合法：</font></br>
```
0:000> 
eax=013a0000 ebx=013a0258 ecx=013a0000 edx=013a0258 esi=00000000 edi=00000004
eip=77a6008d esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapFindListLookupEntry+0x14:
77a6008d 8b5318          mov     edx,dword ptr [ebx+18h] ds:002b:013a0270=013a00c0
......
0:000> 
eax=013a0000 ebx=013a0258 ecx=013a0000 edx=013a00c0 esi=00000000 edi=00000004
eip=77a60099 esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x20:
77a60099 8b4a04          mov     ecx,dword ptr [edx+4] ds:002b:013a00c4=013a04d8
0:000> 
eax=013a0000 ebx=013a0258 ecx=013a04d8 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600ad esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x34:
77a600ad 83c1f8          add     ecx,0FFFFFFF8h
0:000> 
eax=013a0000 ebx=013a0258 ecx=013a04d0 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600b3 esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz ac po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000213
ntdll!RtlpHeapFindListLookupEntry+0x3a:
77a600b3 8b09            mov     ecx,dword ptr [ecx]  ds:002b:013a04d0=70bf6d99
0:000> 
eax=013a0000 ebx=013a0258 ecx=70bf6d99 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600ba esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0x41:
77a600ba 334850          xor     ecx,dword ptr [eax+50h] ds:002b:013a0050=13bf6cfb
0:000> 
eax=013a0000 ebx=013a0258 ecx=63000162 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600bd esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x44:
77a600bd 894df8          mov     dword ptr [ebp-8],ecx ss:002b:010ff664=0000007f
0:000> 
eax=013a0000 ebx=013a0258 ecx=63000162 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600c0 esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x47:
77a600c0 8b45f8          mov     eax,dword ptr [ebp-8] ss:002b:010ff664=63000162
0:000> 
eax=63000162 ebx=013a0258 ecx=63000162 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600c3 esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x4a:
77a600c3 c1e808          shr     eax,8
0:000> 
eax=00630001 ebx=013a0258 ecx=63000162 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600c6 esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x4d:
77a600c6 c1e910          shr     ecx,10h
0:000> 
eax=00630001 ebx=013a0258 ecx=00006300 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600c9 esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0x50:
77a600c9 32c8            xor     cl,al
0:000> 
eax=00630001 ebx=013a0258 ecx=00006301 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600cb esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x52:
77a600cb 8b45f8          mov     eax,dword ptr [ebp-8] ss:002b:010ff664=63000162
0:000> 
eax=63000162 ebx=013a0258 ecx=00006301 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600ce esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x55:
77a600ce 32c8            xor     cl,al
0:000> 
eax=63000162 ebx=013a0258 ecx=00006363 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600d0 esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0x57:
77a600d0 c1e818          shr     eax,18h
0:000> 
eax=00000063 ebx=013a0258 ecx=00006363 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600d3 esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0x5a:
77a600d3 3ac1            cmp     al,cl
......
0:000> 
eax=013a0000 ebx=013a0258 ecx=fffffea2 edx=013a00c0 esi=00000000 edi=00000004
eip=77a600fc esp=010ff648 ebp=010ff66c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x83:
77a600fc 8b0a            mov     ecx,dword ptr [edx]  ds:002b:013a00c0=013a04d8
......
......
......
```
&emsp;&emsp;<font size=2>然后`RtlpHeapFindListLookupEntry`返回了`FreeList`的`Flink`指向的堆块，在这里就是尾块。然后对尾块的`Blink`指向的堆块的`Flink`进行了检查，其必须指向尾块自己：</font></br>
```
0:000> 
eax=013a0498 ebx=013a00c0 ecx=63000162 edx=013a04d8 esi=013a0490 edi=013a0000
eip=77a5e631 esp=010ff690 ebp=010ff758 iopl=0         nv up ei ng nz na po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000283
ntdll!RtlpFreeHeap+0x9c1:
77a5e631 8b4a04          mov     ecx,dword ptr [edx+4] ds:002b:013a04dc=013a00c0
0:000> 
eax=013a0498 ebx=013a00c0 ecx=013a00c0 edx=013a04d8 esi=013a0490 edi=013a0000
eip=77a5e634 esp=010ff690 ebp=010ff758 iopl=0         nv up ei ng nz na po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000283
ntdll!RtlpFreeHeap+0x9c4:
77a5e634 8b19            mov     ebx,dword ptr [ecx]  ds:002b:013a00c0=013a04d8
0:000> 
eax=013a0498 ebx=013a04d8 ecx=013a00c0 edx=013a04d8 esi=013a0490 edi=013a0000
eip=77a5e636 esp=010ff690 ebp=010ff758 iopl=0         nv up ei ng nz na po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000283
ntdll!RtlpFreeHeap+0x9c6:
77a5e636 3bda            cmp     ebx,edx
0:000> 
eax=013a0498 ebx=013a04d8 ecx=013a00c0 edx=013a04d8 esi=013a0490 edi=013a0000
eip=77a5e638 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x9c8:
77a5e638 750c            jne     ntdll!RtlpFreeHeap+0x9d6 (77a5e646)     [br=0]
0:000> u 77a5e646
ntdll!RtlpFreeHeap+0x9d6:
77a5e646 6a00            push    0
77a5e648 53              push    ebx
77a5e649 6a00            push    0
77a5e64b 52              push    edx
77a5e64c 33d2            xor     edx,edx
77a5e64e 8d4a0d          lea     ecx,[edx+0Dh]
77a5e651 e8b9260b00      call    ntdll!RtlpLogHeapFailure (77b10d0f)
77a5e656 0fb706          movzx   eax,word ptr [esi]
```
&emsp;&emsp;<font size=2>其意义相当于如下伪代码：</font></br>
```C
//在这里Chunk代表FreeList的Flink指向的堆块
assert(Chunk->Blink->Flink == Chunk)
```
&emsp;&emsp;<font size=2>然后重新将新堆链入空闲双向循环链表：</font></br>
```
0:000> t
eax=013a0498 ebx=013a04d8 ecx=013a00c0 edx=013a04d8 esi=013a0490 edi=013a0000
eip=77a5e63a esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x9ca:
77a5e63a 8910            mov     dword ptr [eax],edx  ds:002b:013a0498=013a04d8
0:000> 
eax=013a0498 ebx=013a04d8 ecx=013a00c0 edx=013a04d8 esi=013a0490 edi=013a0000
eip=77a5e63c esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x9cc:
77a5e63c 894804          mov     dword ptr [eax+4],ecx ds:002b:013a049c=013a00c0
0:000> 
eax=013a0498 ebx=013a04d8 ecx=013a00c0 edx=013a04d8 esi=013a0490 edi=013a0000
eip=77a5e63f esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x9cf:
77a5e63f 8901            mov     dword ptr [ecx],eax  ds:002b:013a00c0=013a04d8
0:000> 
eax=013a0498 ebx=013a04d8 ecx=013a00c0 edx=013a04d8 esi=013a0490 edi=013a0000
eip=77a5e641 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0x9d1:
77a5e641 894204          mov     dword ptr [edx+4],eax ds:002b:013a04dc=013a00c0
```
&emsp;&emsp;<font size=2>同样伪代码如下：</font></br>
```C
//在这里Chunk代表我们释放后合并的新堆块
Chunk->Flink = TailChunk;
Chunk->Blink = FreeList;
TailChunk->Blink = Chunk;
FreeList->Flink = Chunk;
```
&emsp;&emsp;<font size=2>然后调用了`RtlpHeapAddListEntry`将我们新的堆块写入`EmptyList`:</font></br>
```
0:000> 
eax=0000007f ebx=00000004 ecx=013a0000 edx=00000000 esi=00000004 edi=013a0258
eip=77a7b6e8 esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapAddListEntry+0x3e:
77a7b6e8 8b4f20          mov     ecx,dword ptr [edi+20h] ds:002b:013a0278=013a028c
0:000> 
eax=0000007f ebx=00000004 ecx=013a028c edx=00000000 esi=00000004 edi=013a0258
eip=77a7b6eb esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapAddListEntry+0x41:
77a7b6eb 8b450c          mov     eax,dword ptr [ebp+0Ch] ss:002b:010ff684=013a0498
0:000> 
eax=013a0498 ebx=00000004 ecx=013a028c edx=00000000 esi=00000004 edi=013a0258
eip=77a7b6ee esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpHeapAddListEntry+0x44:
77a7b6ee 890499          mov     dword ptr [ecx+ebx*4],eax ds:002b:013a029c=00000000
```
&emsp;&emsp;<font size=2>然后将`SizeMap`的相关位置处置为新堆的大小：</font></br>
```
0:000> 
eax=013a0498 ebx=00000004 ecx=013a027c edx=00000000 esi=00000004 edi=013a0258
eip=77a7b700 esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapAddListEntry+0x56:
77a7b700 8b0491          mov     eax,dword ptr [ecx+edx*4] ds:002b:013a027c=00000000
0:000> 
eax=00000000 ebx=00000004 ecx=013a027c edx=00000000 esi=00000004 edi=013a0258
eip=77a7b703 esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapAddListEntry+0x59:
77a7b703 0fabf0          bts     eax,esi
0:000> 
eax=00000010 ebx=00000004 ecx=013a027c edx=00000000 esi=00000004 edi=013a0258
eip=77a7b706 esp=010ff658 ebp=010ff678 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapAddListEntry+0x5c:
77a7b706 890491          mov     dword ptr [ecx+edx*4],eax ds:002b:013a027c=00000000
```
&emsp;&emsp;<font size=2>重新加密新的堆块头：</font></br>
```
0:000> 
eax=00000010 ebx=013a04d8 ecx=013a027c edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e786 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0xb16:
77a5e786 8a4602          mov     al,byte ptr [esi+2]        ds:002b:013a0492=00
0:000> 
eax=00000000 ebx=013a04d8 ecx=013a027c edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e789 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpFreeHeap+0xb19:
77a5e789 324601          xor     al,byte ptr [esi+1]        ds:002b:013a0491=00
0:000> 
eax=00000000 ebx=013a04d8 ecx=013a027c edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e78c esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!RtlpFreeHeap+0xb1c:
77a5e78c 3206            xor     al,byte ptr [esi]          ds:002b:013a0490=04
0:000> 
eax=00000004 ebx=013a04d8 ecx=013a027c edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e78e esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0xb1e:
77a5e78e 884603          mov     byte ptr [esi+3],al        ds:002b:013a0493=02
0:000> 
eax=00000004 ebx=013a04d8 ecx=013a027c edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e791 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0xb21:
77a5e791 8b4750          mov     eax,dword ptr [edi+50h] ds:002b:013a0050=13bf6cfb
0:000> 
eax=13bf6cfb ebx=013a04d8 ecx=013a027c edx=00000000 esi=013a0490 edi=013a0000
eip=77a5e794 esp=010ff690 ebp=010ff758 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpFreeHeap+0xb24:
77a5e794 3106            xor     dword ptr [esi],eax  ds:002b:013a0490=04000004
```

---
### 流程总结
- 0. 释放第二个堆块；
- 1. 解密此堆块的对块头并检查HeapCookie；
- 2. 当上一个堆块为空闲态时解密之并进行检查Cookie、Flink和Blink指向堆块的合法性；
- 3. 置零之前堆块的EmptyList和SizeMap记录，并将其从空闲循环双向链表中脱链；
- 4. 脱链后重新计算新堆块的大小并修改，然后根据新大小寻址新堆的下一个堆块检验其Cookie；
- 5. 检查FreeList的Flink和Blink的合法性；
- 6. 将新堆链入空闲循环双向链表；
- 7. 设置EmtryList和SizeMap的相关位置为新堆块信息；
- 8. 加密新堆块的头部然后返回。

### unsafe-unlink的思考
&emsp;&emsp;<font size=2>我们可以看到堆是经过了重重保护的，要想在堆上做手脚着实非常非常困难，首先假设我们可以泄露出`HeapCookie`，然后我们就可以用这种方式绕过第一层检查：</font></br>
```C
    unsigned char* ptr;
    ptr=buf;
    *(unsigned int*)ptr=*(unsigned int*)((unsigned char*)hp+0x50);  //伪造HeapCookie
    ptr=ptr+12;
    *(unsigned int*)ptr=(unsigned int)p1;               //伪造Chunk1的地址
    *(unsigned int*)(ptr+4)=(unsigned int)p1;           //伪造Chunk1的地址
    ptr=(unsigned char*)p1;
    *(unsigned int*)ptr=(unsigned int)buf+8;            //伪造Chunk1->Flink->Blink
    *(unsigned int*)(ptr+4)=(unsigned int)buf+12;       //伪造Chunk1->Blink->Flink
```
&emsp;&emsp;<font size=2>熟悉unsafe unlink的同学肯定一眼就能看懂上面这些利用技巧，然后事实上也成功过了第一层校验，然而高兴得太早了。</font></br>
&emsp;&emsp;<font size=2>执行流一直往下到了脱钩操作`PreChunk->Flink->Blink=PreChunk->Blink->Flink`时，因为我们已经修改了第一个堆块的`Flink`和`Blink`指针，因此的确是完成了一次DWORD SHOOT：`*(unsigned int*)&Array[8]=&Array[12]`，但是也因此使第一个堆块未能正常脱钩。</font></br>

```
0:000> 
eax=00683888 ebx=01570490 ecx=0068388c edx=00000000 esi=015704a0 edi=01570000
eip=7752e0a3 esp=012ffaa0 ebp=012ffb68 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
ntdll!RtlpFreeHeap+0x433:
7752e0a3 8901            mov     dword ptr [ecx],eax  ds:002b:0068388c=01570498
0:000> 
eax=00683888 ebx=01570490 ecx=0068388c edx=00000000 esi=015704a0 edi=01570000
eip=7752e0a5 esp=012ffaa0 ebp=012ffb68 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
ntdll!RtlpFreeHeap+0x435:
7752e0a5 894804          mov     dword ptr [eax+4],ecx ds:002b:0068388c=00683888
0:000> 
eax=00683888 ebx=01570490 ecx=0068388c edx=00000000 esi=015704a0 edi=01570000
eip=7752e0a8 esp=012ffaa0 ebp=012ffb68 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
ntdll!RtlpFreeHeap+0x438:
7752e0a8 f6430208        test    byte ptr [ebx+2],8         ds:002b:01570492=00
0:000> dd 683880
00683880  2cd68615 00000000 00000000 0068388c
00683890  01570498 00000000 00000000 00000000
006838a0  00000000 00000000 00000000 00000000
006838b0  00000000 00000000 00000000 00000000
006838c0  00000000 00000000 00000000 00000000
006838d0  00000000 00000000 00000000 00000000
006838e0  00000000 00000000 00000000 00000000
006838f0  00000000 00000000 00000000 00000000
0:000> dt ntdll!_LIST_ENTRY 15700c0
 [ 0x1570498 - 0x15704d8 ]
   +0x000 Flink            : 0x01570498 _LIST_ENTRY [ 0x683888 - 0x68388c ]
   +0x004 Blink            : 0x015704d8 _LIST_ENTRY [ 0x15700c0 - 0x1570498 ]
```

&emsp;&emsp;<font size=2>最后仍然校验了第一个堆块的`HeapCookie`，而第一个堆块的堆块头已经是合并后的新大小，因此不可能满足条件：</font></br>

```
0:000> 
eax=01570000 ebx=01570258 ecx=fffffea2 edx=015700c0 esi=00000000 edi=00000004
eip=775300fc esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0x83:
775300fc 8b0a            mov     ecx,dword ptr [edx]  ds:002b:015700c0=01570498
0:000> 
eax=01570000 ebx=01570258 ecx=01570490 edx=015700c0 esi=00000000 edi=00000004
eip=7753010a esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz ac pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000217
ntdll!RtlpHeapFindListLookupEntry+0x91:
7753010a 8b09            mov     ecx,dword ptr [ecx]  ds:002b:01570490=02000004
0:000> 
eax=01570000 ebx=01570258 ecx=02000004 edx=015700c0 esi=00000000 edi=00000004
eip=77530111 esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0x98:
77530111 334850          xor     ecx,dword ptr [eax+50h] ds:002b:01570050=2cd68615
0:000> 
eax=01570000 ebx=01570258 ecx=2ed68611 edx=015700c0 esi=00000000 edi=00000004
eip=77530114 esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0x9b:
77530114 894df8          mov     dword ptr [ebp-8],ecx ss:002b:012ffa74=63000162
0:000> 
eax=01570000 ebx=01570258 ecx=2ed68611 edx=015700c0 esi=00000000 edi=00000004
eip=77530117 esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0x9e:
77530117 8b45f8          mov     eax,dword ptr [ebp-8] ss:002b:012ffa74=2ed68611
0:000> 
eax=2ed68611 ebx=01570258 ecx=2ed68611 edx=015700c0 esi=00000000 edi=00000004
eip=7753011a esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0xa1:
7753011a c1e808          shr     eax,8
0:000> 
eax=002ed686 ebx=01570258 ecx=2ed68611 edx=015700c0 esi=00000000 edi=00000004
eip=7753011d esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
ntdll!RtlpHeapFindListLookupEntry+0xa4:
7753011d c1e910          shr     ecx,10h
0:000> 
eax=002ed686 ebx=01570258 ecx=00002ed6 edx=015700c0 esi=00000000 edi=00000004
eip=77530120 esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na po cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000203
ntdll!RtlpHeapFindListLookupEntry+0xa7:
77530120 32c8            xor     cl,al
0:000> 
eax=002ed686 ebx=01570258 ecx=00002e50 edx=015700c0 esi=00000000 edi=00000004
eip=77530122 esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0xa9:
77530122 8b45f8          mov     eax,dword ptr [ebp-8] ss:002b:012ffa74=2ed68611
0:000> 
eax=2ed68611 ebx=01570258 ecx=00002e50 edx=015700c0 esi=00000000 edi=00000004
eip=77530125 esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0xac:
77530125 32c8            xor     cl,al
0:000> 
eax=2ed68611 ebx=01570258 ecx=00002e41 edx=015700c0 esi=00000000 edi=00000004
eip=77530127 esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
ntdll!RtlpHeapFindListLookupEntry+0xae:
77530127 c1e818          shr     eax,18h
0:000> 
eax=0000002e ebx=01570258 ecx=00002e41 edx=015700c0 esi=00000000 edi=00000004
eip=7753012a esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei pl nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000207
ntdll!RtlpHeapFindListLookupEntry+0xb1:
7753012a 3ac1            cmp     al,cl
0:000> 
eax=0000002e ebx=01570258 ecx=00002e41 edx=015700c0 esi=00000000 edi=00000004
eip=7753012c esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000287
ntdll!RtlpHeapFindListLookupEntry+0xb3:
7753012c 0f85a8930400    jne     ntdll!RtlpHeapFindListLookupEntry+0x49461 (775794da) [br=1]
0:000> 
eax=0000002e ebx=01570258 ecx=00002e41 edx=015700c0 esi=00000000 edi=00000004
eip=775794da esp=012ffa58 ebp=012ffa7c iopl=0         nv up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000287
ntdll!RtlpHeapFindListLookupEntry+0x49461:
775794da 8b55fc          mov     edx,dword ptr [ebp-4] ss:002b:012ffa78=01570000
```

&emsp;&emsp;<font size=2>综上，如果使用常规的`unsafe unlink`的话就会使`HeapCookie`检验无法通过，因此无法利用。除非堆块头未加密，但未加密的情况基本只会在调试器里看到了，因此这一技术基本无法在现实中使用了，堆溢出的unlink利用还是另寻出路吧（~~Wdnmd还真就用不了啊~~）。</font></br>

