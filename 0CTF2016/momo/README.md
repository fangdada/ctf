# 0CTF2016 momo_3

## Author: fanda

&nbsp; &nbsp; &nbsp; &nbsp; <font size=2>接下来我们看看另一题momo_3，这是一个经过mov混淆的二进制程序，用静态分析会十分艰难，所以使用动态调试一边分析逻辑一边思考解法，直接下断在fgets函数，随意输入0123456之后，下硬件断点观察自己的输入何时被读取或者修改。断点触发后我们看到我们输入的第一个字节'0'被取出来与一个常数9一起被存储：</font></br>

```assembly
EAX  0x30
EBX  0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— xor    al, 0x6f /* 0x26f34 */
ECX  0x0
EDX  0x9
...........
...........
0x804a7ab    mov    eax, dword ptr [0x8055740]
0x804a7b0    mov    edx, dword ptr [0x805574c]
0x804a7b6    mov    dword ptr [0x85fe870], 0xcc00008e
0x804a7c0    mov    dword ptr [0x81fe6e0], eax
0x804a7c5    mov    dword ptr [0x81fe6e4], edx
0x804a7cb    mov    dword ptr [0x85fe870], 0xcc00008f
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>继续trace，分析逻辑可以看到，程序通过查两次表实现了加法，原理就是有一张表[0,1,2,3,4,5...]，然后用mov[表+edx*4]的方式得到0x30的地址，然后再在这个地址的基础上进行一次类似之前的mov就可以得到0x30再偏移9的地址得到0x39，反汇编如下：</font></br>

```assembly
   0x804a7f3    mov    ax, word ptr [0x81fe6e0]
   0x804a7f9    mov    cx, word ptr [0x81fe6e4]
   0x804a800    mov    edx, dword ptr [eax*4 + 0x8069620]
   0x804a807    mov    edx, dword ptr [edx + ecx*4]
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>加法完成后，发现eax和edx寄存器加载了一个结果和一个密文，反汇编：</font></br>

```assembly
   0x804a87b    mov    eax, dword ptr [0x8055740]
   0x804a880    mov    edx, dword ptr [0x8055748]
   0x804a886    mov    dword ptr [0x85fe870], 0xcc000093
   0x804a890    mov    dword ptr [0x81fe6e0], eax
   0x804a895    mov    dword ptr [0x81fe6e4], edx
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>猜测是要让两个寄存器结果相等（事实上后续通过两个寄存器用查表的方式实现的异或进行了一次异或，结果必须为0），计算可以得到第一个输入应是'0'，然后继续trace下去可以发现逻辑基本就是这样，减法也是通过两次查表实现的，计算得到第二个输入为'c'，第三个为't'，第四个'f'，第五个'{'，那么猜测就没错了，然后通过trace可以得到所有的密文和加减的常数，最后写一个脚本就可以跑到flag：</font></br>

```python
#!/bin/env python

Operate=['+','-','-','+','-','-','+','+','+','-','+','+','+','+','-','-','+','+','+','-','+','-','-','+','-','+','-','-']
Table1=[0x9,0x2,0x7,0xF,0x7,0x7,0x9,0x4,0xE,0x8,0x13,0x6,0x1,0x1,0x3,0x1,0x9,0x0,0x9,0x9,0x9,0x2,0x1,0xA,0x5,0x6,0,0]
Table2=[0x39,0x61,0x6D,0x75,0x74,0x66,0x39,0x5A,0x6D,0x41,0x48,0x65,0x75,0x56,0x75,0x30,0x57,0x39,0x68,0x5A,0x39,0x4E,0x30,0x4F,0x6F,0x39,0x21,0x7D]
flag=[]

for i,j,o in zip(Table1,Table2,Operate):
    c=j-i if o=='+' else j+i
    flag.append(chr(c))

print len(Operate)
print len(Table1)
print len(Table2)

print ''.join(flag)
#0ctf{m0V_I5_tUr1N9_c0P1Et3!}
```

