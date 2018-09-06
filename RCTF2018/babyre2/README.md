# RCTF2018 babyre2
## Author: 文火
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>还是打算将以前的wp都放上来方便自己也方便别人一起学习复习了。这篇[脚本](https://bbs.pediy.com/thread-226930.htm)参考看雪里的无名侠大佬复现的。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>整个程序并不难，会用z3的话分分钟就能解出来了，伪代码里诸如_mm_load_si128这样的宏定义比较多，可以参考我放在githuub上的[常用宏定义](https://github.com/fangdada/ctf/tree/master/how2reverse/ida_define.c)找一下。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>至于里面的难点大概就是：</font></br>

```C
unsigned __int64 __usercall sub_400BA0@<rax>(unsigned __int64 constant@<rdx>, unsigned __int64 zero@<rcx>, __int64 a3@<rbp>, __int128 a4@<rsi:rdi>)
{
  unsigned __int64 v4; // r10
  unsigned __int64 result; // rax
  unsigned __int64 v6; // rdx
  __int64 v7; // rbp
  int v8; // ebp
  unsigned __int64 v9; // rbx
  unsigned __int64 v10; // r10
  unsigned __int64 v11; // r8
  unsigned __int128 v12; // tt
  unsigned __int64 v13; // rsi
  unsigned __int128 v14; // ax
  unsigned __int64 v15; // rcx
  unsigned __int64 v16; // rdi
  unsigned __int128 v17; // ax
  unsigned __int128 v18; // tt

  v4 = constant;
  result = a4;
  if ( zero )
  {
    if ( zero > *((_QWORD *)&a4 + 1) )
    {
      result = a4;
    }
    else
    {
      _BitScanReverse64((unsigned __int64 *)&v7, zero);
      v8 = v7 ^ 0x3F;
      if ( v8 )
      {
        v9 = constant << v8;
        v10 = (zero << v8) | (constant >> (64 - (unsigned __int8)v8));
        v11 = (_QWORD)a4 << v8;
        *(_QWORD *)&v12 = ((unsigned __int64)a4 >> (64 - (unsigned __int8)v8)) | (*((_QWORD *)&a4 + 1) << v8);
        *((_QWORD *)&v12 + 1) = *((_QWORD *)&a4 + 1) >> (64 - (unsigned __int8)v8);
        v13 = v12 % v10;
        v14 = (constant << v8) * (unsigned __int128)(unsigned __int64)(v12 / v10);
        v15 = v9 * (unsigned __int128)(unsigned __int64)(v12 / v10) >> 64;
        v16 = v9 * (v12 / v10);
        if ( v13 < *((_QWORD *)&v14 + 1) || v13 == *((_QWORD *)&v14 + 1) && v11 < (unsigned __int64)v14 )
        {
          v17 = v14 - __PAIR__(v10, v9);
          v15 = *((_QWORD *)&v17 + 1);
          v16 = v17;
        }
        result = ((v11 - v16) >> v8) | ((__PAIR__(v13, v11) - __PAIR__(v15, v16)) >> 64 << (64 - (unsigned __int8)v8));
      }
      else if ( zero < *((_QWORD *)&a4 + 1) || constant <= (unsigned __int64)a4 )
      {
        result = a4 - constant;
      }
    }
  }
  else
  {
    if ( constant <= *((_QWORD *)&a4 + 1) )
    {
      if ( !constant )
        v4 = 1 / 0uLL;
      *(_QWORD *)&v18 = a4;
      *((_QWORD *)&v18 + 1) = *((_QWORD *)&a4 + 1) % v4;
      v6 = v18 % v4;
    }
    else
    {
      v6 = a4 % (unsigned __int128)constant;
    }
    result = v6;
  }
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>乍一看感觉被吓到了有没有？其实仔细分析一下这里面好多都是垃圾代码，真正会执行的也就下面这个if，if(0)是不执行的。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>还有一点就是这里都是128位的大数，需要求解一个乘法逆元可能比较困难，不过无名侠大佬也提出了公式:</font></br>

```C
a*b%c=d
a=d*b^(c-2)%c
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>使用灵活性这么强的python解一下就可以了，其他难点也没有了，所以直接给出脚本（当然也是别人的）：</font></br>

脚本
=======

```python
from z3 import *
 
def fastExpMod(b, e, m):
    result = 1
    while e != 0:
        if (e&1) == 1:
            # ei = 1, then mul
            result = (result * b) % m
        e >>= 1
        # b, b^2, b^4, b^8, ... , b^(2^n)
        b = (b*b) % m
    return result
 
def r(d,b):
    c = 0xFFFFFFFFFFFFFFC5
    s=d*fastExpMod(b,(c-2),c) % c
    return s
print hex(r(0x55555555555559a3,0xFFFFFFFFFFFFFFFF))
xmmword_602060 = 0x7BA58F82BD8980352B7192452905E8FB
xmmword_602070 = 0x163F756FCC221AB0A3112746582E1434
xmmword_602080 = 0xDCDD8B49EA5D7E14ECC78E6FB9CBA1FE
xmmword_602090 = 0xAAAAAAAAAA975D1CA2845FE0B3096F8E
xmmword_6020A0 = 0x55555555555559A355555555555559A3
xmmword_6020B0 = 0x55555555555559A355555555555559A3
xmmword_6020C0 = 0x55555555555559A355555555555559A3
xmmword_6020D0 = 0x55555555555559A355555555555559A3
 
v17 = BitVec('v17',128)
v18 = BitVec('v18',128)
v19 = BitVec('v19',128)
v20 = BitVec('v20',128)
v21 = BitVec('v21',128)
v22 = BitVec('v22',128)
v23 = BitVec('v23',128)
v24 = BitVec('v24',128)
 
 
def _mm_or_si128(a,b):
    return a|b
def _mm_xor_si128(a,b):
    return a^b
def _mm_load_si128(a):
    return a
 
v5 = _mm_or_si128(
         _mm_xor_si128(_mm_load_si128(xmmword_6020D0), v24),
         _mm_or_si128(
           _mm_xor_si128(_mm_load_si128(v23), xmmword_6020C0),
           _mm_or_si128(
             _mm_xor_si128(_mm_load_si128(v22), xmmword_6020B0),
             _mm_or_si128(
               _mm_xor_si128(_mm_load_si128(v21), xmmword_6020A0),
               _mm_or_si128(
                 _mm_xor_si128(_mm_load_si128(v20), xmmword_602090),
                 _mm_or_si128(
                   _mm_xor_si128(_mm_load_si128(v19), xmmword_602080),
                   _mm_or_si128(_mm_xor_si128(v17, xmmword_602060), _mm_xor_si128(_mm_load_si128(xmmword_602070), v18))))))))
b = v5|(v5>>8)
 
s = Solver()
s.add(b == 0)
s.check()
res = s.model()
 
def ascii(x):
    s = ''
    for i in range(8):
        s = s + chr(x & 0xff)
        x = x >> 8
    return s
 
def unp(x,i):
    if i == 0:
        return res[x].as_long() & 0xffffffffffffffff
    else:
        return res[x].as_long() >> 64
 
flag = ascii(r(unp(v17,0),0x20656D6F636C6557))
flag += ascii(r(unp(v17,1),0x2046544352206F74))
 
flag += ascii(r(unp(v18,0),0x6548202138313032))
flag += ascii(r(unp(v18,1),0x2061207369206572))
 
flag += ascii(r(unp(v19,0),0x6320455279626142))
flag += ascii(r(unp(v19,1),0x65676E656C6C6168))
 
flag += ascii(r(unp(v20,0), 0x756F7920726F6620))
flag += ascii(r(unp(v20,1), 0xFFFFFFFFFFFF002E))
 
flag += ascii(r(unp(v21,0), 0xFFFFFFFFFFFFFFFF))
flag += ascii(r(unp(v21,1), 0xFFFFFFFFFFFFFFFF))
 
flag += ascii(r(unp(v22,0), 0xFFFFFFFFFFFFFFFF))
flag += ascii(r(unp(v22,1), 0xFFFFFFFFFFFFFFFF))
 
flag += ascii(r(unp(v23,0), 0xFFFFFFFFFFFFFFFF))
flag += ascii(r(unp(v23,1), 0xFFFFFFFFFFFFFFFF))
 
flag += ascii(r(unp(v24,0), 0xFFFFFFFFFFFFFFFF))
flag += ascii(r(unp(v24,1), 0xFFFFFFFFFFFFFFFF))
print flag
```
