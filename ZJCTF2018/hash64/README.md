# 湘湖杯2018 Hash
## Wenhuo
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>典型的逆向题，肝就完事了，下次不想做这种题了太浪费时间。。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先来看一下主函数：</font></br>

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  __int64 v4; // r8
  __int64 v5; // r9
  signed __int64 v6; // rbx
  signed __int64 size; // rax
  __int64 v8; // rax
  __int64 v9; // rdx
  __int64 v10; // r8
  __int64 v11; // r9
  int v13; // [rsp+20h] [rbp-138h]
  char Dst[8]; // [rsp+30h] [rbp-128h]
  char v15[264]; // [rsp+38h] [rbp-120h]

  memset(Dst, 0, 0x104ui64);
  printf((__int64)"Please enter flag(Note:hxb2018{digital}:", v3, v4, v5);
  gets_s(Dst, 0x104ui64);
  v6 = -1i64;
  size = -1i64;
  do
    ++size;
  while ( Dst[size] );
  v13 = size;
  if ( check_hash((__int64)&v13, 4ui64) != 0xD31580A28DD8E6C4i64 )
    exit(1);
  v8 = (unsigned int)(v13 - 1);
  if ( (unsigned int)v8 >= 0x104 )
  {
    _report_rangecheckfailure();
    JUMPOUT(*(_QWORD *)&byte_1400019E1);
  }
  Dst[v8] = 0;
  do
    ++v6;
  while ( v15[v6] );
  if ( check_hash((__int64)v15, (unsigned int)v6) != 0xAA302D9E67AAC4BAi64 )
    exit(1);
  printf((__int64)"successful!\nplease entry any key exit...", v9, v10, v11);
  fgetchar();
  return 0;
}
```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>（已重命名）主要由check_hash函数来判断输入长度和flag的正确性。进入check_hash函数可以看到这样：</font></br>


```C
__int64 __fastcall sub_1400017A0(__int64 flag, unsigned __int64 a2)
{
  unsigned __int64 v2; // rsi
  __int64 _flag; // rbp
  __int64 v4; // rdi
  unsigned __int64 v5; // rbx
  unsigned int low6bits; // esi
  signed __int64 v7; // rbx
  __int64 v9; // [rsp+20h] [rbp-A8h]
  __int64 v10; // [rsp+40h] [rbp-88h]
  __int64 v11; // [rsp+60h] [rbp-68h]
  __int64 v12; // [rsp+80h] [rbp-48h]

  v2 = a2;                                      // first: a1=size,a2=4
                                                // second:a1=flag,a2=size
  _flag = flag;
  init_arg2(flag, &v9);
  v4 = 0i64;
  if ( v2 >= 0x20 )
  {
    v5 = 32i64;
    do
    {
      sub_140001250((unsigned __int8 *)(v5 + _flag - 32), &v9);
      v4 += 32i64;
      v5 += 32i64;
    }
    while ( v5 <= v2 );
  }
  low6bits = v2 & 0x1F;
  if ( low6bits )
    first_hash(v4 + _flag, low6bits, (__int64)&v9);// first: v4=0,low6bits=4
  v7 = 4i64;
  do
  {
    loop_hash(&v9);
    --v7;
  }
  while ( v7 );
  return v12 + v11 + v10 + v9;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先会调用init_arg2生成一段密文用来后续的hash，进入函数内部可以看到是常量操作，跟第一个参数（输入）无关：</font></br>

```C
signed __int64 __fastcall sub_140001000(__int64 a1, _QWORD *a2)
{
  signed __int64 result; // rax

  a2[8] = 0x1BE6D5D5FE4CCE2Fi64;
  a2[9] = 0x24093822299F31D0i64;
  a2[10] = 0x33198A2E03707344i64;
  a2[11] = 0x443F6A8885A308D3i64;
  a2[12] = 0x5BD39E10CB0EF593i64;
  a2[13] = 0x60ACF169B5F18A8Ci64;
  a2[14] = 0x7E5466CF34E90C6Ci64;
  a2[15] = 0x852821E638D01377i64;
  *a2 = 0xCF0C0C1ED5EDF3Ei64;
  a2[1] = a2[9] ^ 0x3F3E3D3C3B3A1918i64;
  a2[2] = a2[10] ^ 0x1226252423222121i64;
  a2[3] = a2[11] ^ 0x2F2E2D2C2B2A2928i64;
  a2[4] = a2[12] ^ 0x1312111117161514i64;
  a2[5] = a2[13] ^ 0x3B3A19183F3E3D3Ci64;
  a2[6] = a2[14] ^ 0x2322212112262524i64;
  result = a2[15] ^ 0x2B2A29282F2E2D2Ci64;
  a2[7] = result;
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>回到上一个函数，事实上无论是第一个hash还是第二个hash，if(v2>=0x20)这一代码块根本就不会执行，跳过他，继续往下看，进入first_hash函数：</font></br>

```C
__int64 __fastcall sub_1400014D0(__int64 flag, __int64 a2, __int64 a3)
{
  char _size; // di
  __int64 _table; // rbx
  __int64 v5; // r8
  signed __int64 low2bits; // r10
  unsigned __int64 v7; // r9
  _BYTE *v8; // r11
  char v9; // cl
  signed __int64 v10; // rdx
  int v11; // eax
  __int64 v12; // rcx
  int v13; // eax
  __int64 v14; // rcx
  int v15; // eax
  int v16; // edx
  __int64 v17; // r8
  char *v18; // rax
  char v20; // [rsp+20h] [rbp-38h]
  __int64 v21; // [rsp+21h] [rbp-37h]
  __int64 v22; // [rsp+29h] [rbp-2Fh]
  __int64 v23; // [rsp+31h] [rbp-27h]
  int v24; // [rsp+39h] [rbp-1Fh]
  __int16 v25; // [rsp+3Dh] [rbp-1Bh]
  char v26; // [rsp+3Fh] [rbp-19h]

  _size = a2;                                   // a2=4,a3=table
                                                // now:
                                                // a2=10,a3=table
  v20 = 0;
  _table = a3;
  v21 = 0i64;
  v5 = flag;
  v22 = 0i64;
  low2bits = a2 & 0xFFFFFFFFFFFFFFFCui64;       // first:low2bits=0
  v23 = 0i64;
  v7 = a2 & 3;
  v24 = 0;
  v25 = 0;
  v26 = 0;
  v8 = (_BYTE *)((a2 & 0xFFFFFFFFFFFFFFFCui64) + flag);
  v9 = a2;
  v10 = 0x100000001i64 * a2;                    // v10=0x400000004
  *(_QWORD *)_table += v10;
  *(_QWORD *)(_table + 8) += v10;
  *(_QWORD *)(_table + 16) += v10;
  *(_QWORD *)(_table + 24) += v10;
  v11 = *(_DWORD *)(_table + 40);
  *(_QWORD *)(_table + 32) = (unsigned int)__ROL4__(*(_DWORD *)(_table + 32), v9) | ((unsigned __int64)(unsigned int)__ROL4__(*(_QWORD *)(_table + 32) >> 32, v9) << 32);
  v12 = (unsigned int)__ROL4__(v11, _size);
  v13 = *(_DWORD *)(_table + 48);
  *(_QWORD *)(_table + 40) = v12 | ((unsigned __int64)(unsigned int)__ROL4__(*(_QWORD *)(_table + 40) >> 32, _size) << 32);
  v14 = (unsigned int)__ROL4__(v13, _size);
  v15 = *(_DWORD *)(_table + 56);
  *(_QWORD *)(_table + 48) = v14 | ((unsigned __int64)(unsigned int)__ROL4__(*(_QWORD *)(_table + 48) >> 32, _size) << 32);
  *(_QWORD *)(_table + 56) = (unsigned int)__ROL4__(v15, _size) | ((unsigned __int64)(unsigned int)__ROL4__(
                                                                                                     *(_QWORD *)(_table + 56) >> 32,
                                                                                                     _size) << 32);
  v16 = 0;
  if ( low2bits > 0 )                           // second:
                                                // low2bits=8
  {
    v17 = v5 - (_QWORD)&v20;
    v18 = &v20;
    do
    {
      ++v16;
      *v18 = v18[v17];
      ++v18;
    }
    while ( v16 < low2bits );
  }
  if ( _size & 0x10 )
  {
    HIBYTE(v24) = v8[v7 - 4];
    v25 = *(_WORD *)&v8[v7 - 3];
    v26 = v8[v7 - 1];
  }
  else if ( v7 )                                // second:
                                                // v7=2
  {
    HIBYTE(v22) = *v8;
    LOBYTE(v23) = v8[v7 >> 1];
    BYTE1(v23) = v8[v7 - 1];
  }
  return sub_140001250((unsigned __int8 *)&v20, (_QWORD *)_table);
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>程序开始显露出他原本的狰狞面目了，变得复杂，不急，慢慢看，v10像是一个seed，乘上第二个参数size之后对密文（仍然是常量操作，不用管输入)进行第二次变换，无论输入怎么样，动态调试的时候这一块密文都会是同样的，往后的两个if一个elseif代码块都不会执行（变得简单多了把？），继续步入sub_140001250，又一个大家伙：</font></br>

```C
__int64 __fastcall sub_140001250(unsigned __int8 *flag, _QWORD *a2)
{
  unsigned __int8 *v2; // r8
  _QWORD *table; // r13
  unsigned __int64 v4; // rdx
  __int64 v5; // rcx
  __int64 v6; // rax
  unsigned __int64 v7; // rcx
  __int64 v8; // rax
  unsigned __int64 v9; // rcx
  _QWORD *table_ptr; // rax
  char *v11; // rbx
  signed __int64 v12; // r11
  __int64 v13; // r8
  unsigned __int64 v14; // r10
  __int64 v15; // rdx
  __int64 v16; // rcx
  __int64 v17; // rdx
  unsigned __int64 v19; // [rsp+20h] [rbp-58h]
  unsigned __int64 v20; // [rsp+28h] [rbp-50h]
  unsigned __int64 v21; // [rsp+30h] [rbp-48h]
  unsigned __int64 v22; // [rsp+38h] [rbp-40h]

  v2 = flag;
  table = a2;
  v4 = *flag | ((flag[1] | ((flag[2] | ((flag[3] | ((flag[4] | ((flag[5] | ((unsigned __int64)*((unsigned __int16 *)flag
                                                                                              + 3) << 8)) << 8)) << 8)) << 8)) << 8)) << 8);
  v5 = *((unsigned __int16 *)flag + 7);
  v19 = v4;
  v6 = v2[22];
  v20 = v2[8] | ((v2[9] | ((v2[10] | ((v2[11] | ((v2[12] | ((v2[13] | (unsigned __int64)(v5 << 8)) << 8)) << 8)) << 8)) << 8)) << 8);
  v7 = v2[16] | ((v2[17] | ((v2[18] | ((v2[19] | ((v2[20] | ((v2[21] | ((v6 | ((unsigned __int64)v2[23] << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8);
  v8 = v2[30];
  v21 = v7;
  v9 = v2[24] | ((v2[25] | ((v2[26] | ((v2[27] | ((v2[28] | ((v2[29] | ((v8 | ((unsigned __int64)v2[31] << 8)) << 8)) << 8)) << 8)) << 8)) << 8)) << 8);
  table_ptr = table + 8;
  v22 = v9;
  v11 = (char *)((char *)&v19 - (char *)table);
  v12 = 4i64;
  do
  {
    v13 = *(table_ptr - 8);
    v14 = *(table_ptr - 4) + *table_ptr + *(_QWORD *)&v11[(_QWORD)table_ptr - 64];
    v15 = (unsigned int)(*((_DWORD *)table_ptr - 8) + *(_DWORD *)table_ptr + *(_DWORD *)&v11[(_QWORD)table_ptr - 64]);
    v16 = *(table_ptr - 8) >> 32;
    *(table_ptr - 4) = v14;
    ++table_ptr;
    *(table_ptr - 1) ^= v16 * v15;
    v17 = table_ptr[3];
    *(table_ptr - 9) = v13 + v17;
    table_ptr[3] = v17 ^ (unsigned int)(v13 + v17) * (v14 >> 32);
    --v12;
  }
  while ( v12 );
  sub_140001120(table[5], table[4], table + 1, table);
  sub_140001120(table[7], table[6], table + 3, table + 2);
  sub_140001120(table[1], *table, table + 5, table + 4);
  return sub_140001120(table[3], table[2], table + 7, table + 6);
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>看到这头都大了，但仔细一看发现在第一个check_hash函数里面v4这一个变量的内存处其实就是一个size，像这样：</font></br>

```
00000064B7F1F870  13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  
00000064B7F1F880  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................  

```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>而代码：</font></br>
```C
*(_QWORD *)&v11[(_QWORD)table_ptr - 64]
```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其实就会从这一处内存取数据，根据table_ptr++，逐8字节取。然后你就会发现上面一大堆移位置位其实跟下面的hash算法没啥关系:)，唯一有关系的就是我上面发的那一处取内存。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>继续往下看sub_140001120，嗨呀还没完了:</font></br>

```C
signed __int64 __fastcall sub_140001120(__int64 a1, __int64 a2, _QWORD *a3, _QWORD *a4)
{
  signed __int64 result; // rax

  *a4 += a2 & 0xFF0000 | (((a2 << 24) | (unsigned __int16)a2 & 0xFF00) << 32) | ((a1 & 0xFF000000000000FFui64 | ((a1 & 0xFF000000000000i64 | a2 & 0xFF0000000000i64 | ((a1 & 0xFF00000000i64 | (unsigned __int64)((unsigned int)a2 & 0xFF000000)) >> 8)) >> 8)) >> 8);
  result = 0xFF00000000000000i64;
  *a3 += a1 & 0xFF0000 | a2 & 0xFF00000000000000ui64 | (((unsigned __int16)a1 & 0xFF00 | ((unsigned __int64)(unsigned __int8)a1 << 24)) << 24) | ((a2 & 0xFF000000000000i64 | ((a1 & 0xFF0000000000i64 | ((a2 & 0xFF00000000i64 | (unsigned __int64)((unsigned int)a1 & 0xFF000000)) >> 8)) >> 8)) >> 8);
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>还好只是对第三四个参数进行一些移位后的变换赋值而已，非常简单。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>终于看完了check_hash的first_hash，还有一个loop_hash啊哈哈哈：</font></br>

```C
  v7 = 4i64;
  do
  {
    loop_hash(&v9);
    --v7;
  }
  
  
  signed __int64 __fastcall sub_140001660(__int64 *table)
{
  __int64 *v1; // r15
  signed __int64 v2; // rbx
  __int64 *v3; // rax
  signed __int64 v4; // r11
  __int64 v5; // r9
  __int64 v6; // r8
  unsigned __int64 v7; // r10
  unsigned __int64 v8; // rdx
  __int64 v9; // rcx
  __int64 v11; // [rsp+20h] [rbp-58h]
  __int64 v12; // [rsp+28h] [rbp-50h]
  __int64 v13; // [rsp+30h] [rbp-48h]
  __int64 v14; // [rsp+38h] [rbp-40h]

  v1 = table;
  v11 = __ROL8__(table[2], 32);
  v12 = __ROL8__(table[3], 32);
  v13 = __ROL8__(*table, 32);
  v14 = __ROL8__(table[1], 32);
  v2 = (char *)&v11 - (char *)table;
  v3 = table + 8;
  v4 = 4i64;
  do
  {
    v5 = *(v3 - 8);
    v6 = v3[4];
    v7 = *(v3 - 4) + *v3 + *(__int64 *)((char *)v3 + v2 - 64);
    v8 = (unsigned __int64)*(v3 - 8) >> 32;
    v9 = (unsigned int)(*((_DWORD *)v3 - 8) + *(_DWORD *)v3 + *(_DWORD *)((char *)v3 + v2 - 64));
    *(v3 - 4) = v7;
    ++v3;
    *(v3 - 1) ^= v9 * v8;
    *(v3 - 9) = v5 + v6;
    v3[3] = v6 ^ (v7 >> 32) * (unsigned int)(v5 + v6);
    --v4;
  }
  while ( v4 );
  sub_140001120(v1[5], v1[4], v1 + 1, v1);
  sub_140001120(v1[7], v1[6], v1 + 3, v1 + 2);
  sub_140001120(v1[1], *v1, v1 + 5, v1 + 4);
  return sub_140001120(v1[3], v1[2], v1 + 7, v1 + 6);
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>非常起眼的，do while循环中的hash算法，不同的是原来的一处取内存代码不太一样变成了：</font></br>

```C
*(__int64 *)((char *)v3 + v2 - 64)
```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>看不懂没事，我们推算一下，大不了动态调试然后猜：</font></br>

```C
v2 = (char *)&v11 - (char *)table;
v3 = table + 8;
*(__int64 *)((char *)v3 + v2 - 64);

//原式可以得到:
//*(__int64 *)((char *)table + 8 + (char *)&v11 - (char *)table - 64);
//	=====>
//&v11
//注意table+8的8是__int64类型的所以相当于char类型的64。
//结果简单的不可思议？
```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以开头其实就是用\__ROL__(ida宏，不懂的看汇编分析)生成了一系列类似魔数(magic number)的密文表（其实first_check的魔数只是一个[size,0,0,0]，就是之前抓取的内存）。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>随后就是同样的hash算法，只是salt不一样。最后的sub_140001120就不说了。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>很好，第一个hash的检查我们都看了一遍了，所以接下来我们要做的就是：</font></br>
**1.直接从内存中取sub_1400014D0根据种子加密过的init_arg2生成的密文。**</br>
**2.还原hash算法，自己生成魔数。**</br>
**3.爆破之！**</br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>最后我爆破得到的size大小是0x13（所以我说v2>=0x20根本不会执行），除去hxb2018{}这些，剩下的flag就是10位，题目已经提到了这10位是digital（数字），那就使爆破成为了可能（求逆更不可能）。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>第二个hash的check函数算法跟第一个一样，我就不多说了，唯一要注意的就是种子和魔数不一样了，要重新抓取密文，然后生成魔数的代码别写错，比如输入hxb2018{0123456789}得到的hash值是9C8D7E2DED95364E。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>最后放一堆我的脚本：</font></br>

**sub1120.py**
```python
#!/bin/python

'''
  signed __int64 result; // rax

  *temp4 += temp2 & 0xFF0000 | (((temp2 << 24) | (unsigned __int16)temp2 & 0xFF00) << 32) | ((temp1 & 0xFF000000000000FFui64 | ((temp1 & 0xFF000000000000i64 | temp2 & 0xFF0000000000i64 | ((temp1 & 0xFF00000000i64 | (unsigned __int64)((unsigned int)temp2 & 0xFF000000)) >> 8)) >> 8)) >> 8);
  result = 0xFF00000000000000i64;
  *temp3 += temp1 & 0xFF0000 | temp2 & 0xFF00000000000000ui64 | (((unsigned __int16)temp1 & 0xFF00 | ((unsigned __int64)(unsigned __int8)temp1 << 24)) << 24) | ((temp2 & 0xFF000000000000i64 | ((temp1 & 0xFF0000000000i64 | ((temp2 & 0xFF00000000i64 | (unsigned __int64)((unsigned int)temp1 & 0xFF000000)) >> 8)) >> 8)) >> 8);
  return result;



temp4 += temp2 & 0xFF0000 | (((temp2 << 24) | (temp2&0xffff) & 0xFF00) << 32) | ((temp1 & 0xFF000000000000FF | ((temp1 & 0xFF000000000000 | temp2 & 0xFF0000000000 | ((temp1 & 0xFF00000000 | (((temp2&0xffffffff)&0xffffffffffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8)
temp4&=0xffffffffffffffff

temp3 += temp1 & 0xFF0000 | temp2 & 0xFF00000000000000 | (((temp1&0xffff) & 0xFF00 | (((temp1&0xff)&0xffffffffffffffff) << 24)) << 24) | ((temp2 & 0xFF000000000000 | ((temp1 & 0xFF0000000000 | ((temp2 & 0xFF00000000 | ((temp1&0xffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8);
temp3&=0xffffffffffffffff
'''

def encry1120(temp1,temp2,temp3,temp4):

    temp4 += temp2 & 0xFF0000 | (((temp2 << 24) | (temp2&0xffff) & 0xFF00) << 32) | ((temp1 & 0xFF000000000000FF | ((temp1 & 0xFF000000000000 | temp2 & 0xFF0000000000 | ((temp1 & 0xFF00000000 | (((temp2&0xffffffff)&0xffffffffffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8)
    temp4&=0xffffffffffffffff

    temp3 += temp1 & 0xFF0000 | temp2 & 0xFF00000000000000 | (((temp1&0xffff) & 0xFF00 | (((temp1&0xff)&0xffffffffffffffff) << 24)) << 24) | ((temp2 & 0xFF000000000000 | ((temp1 & 0xFF0000000000 | ((temp2 & 0xFF00000000 | ((temp1&0xffffffff) & 0xFF000000)) >> 8)) >> 8)) >> 8);
    temp3&=0xffffffffffffffff

    return temp1,temp2,temp3,temp4


```

**sub1660.py**

```python
#!/bin/python

from sub1120 import *

'''
  v2 = (char *)&table1 - (char *)table;
  table_ptr = table + 8;
  v4 = 4i64;
  do
  {
    v5 = *(table_ptr - 8);
    v6 = table_ptr[4];
    v7 = *(table_ptr - 4) + *table_ptr + *(__int64 *)((char *)table_ptr + v2 - 64);
    v8 = (unsigned __int64)*(table_ptr - 8) >> 32;
    v9 = (unsigned int)(*((_DWORD *)table_ptr - 8) + *(_DWORD *)table_ptr + *(_DWORD *)((char *)table_ptr + v2 - 64));
    *(table_ptr - 4) = v7;
    ++table_ptr;
    *(table_ptr - 1) ^= v9 * v8;
    *(table_ptr - 9) = v5 + v6;
    table_ptr[3] = v6 ^ (v7 >> 32) * (unsigned int)(v5 + v6);
    --v4;
  }
  while ( v4 );
  sub_140001120(table[5], table[4], table + 1, table);
  sub_140001120(table[7], table[6], table + 3, table + 2);
  sub_140001120(table[1], *table, table + 5, table + 4);
  return sub_140001120(table[3], table[2], table + 7, table + 6);

'''

exchg=lambda (x): ((x&0xffffffff00000000)>>32)|((x&0xffffffff)<<32)


def oneloop_encry1660(table):

    table_ptr=[]
    for i in table:
        table_ptr.append(i)

    magic=[]
    magic.append(exchg(table_ptr[2]))
    magic.append(exchg(table_ptr[3]))
    magic.append(exchg(table_ptr[0]))
    magic.append(exchg(table_ptr[1]))

    i=8
    for j in range(4):
        temp1=table_ptr[i-8]
        temp2=table_ptr[i+4]

        temp3=(table_ptr[i-4]+table_ptr[i]+magic[i-8])&0xffffffffffffffff
        temp4=table_ptr[i-8]>>32
        temp5=(table_ptr[i-4]+table_ptr[i]+magic[i-8])&0xffffffff

        table_ptr[i-4]=temp3


        i+=1
        table_ptr[i-1]^=(temp4*temp5)&0xffffffffffffffff
        table_ptr[i-9]=(temp1+temp2)&0xffffffffffffffff
        table_ptr[i+3]=(temp2^(temp3>>32)*((temp1+temp2)&0xffffffff))&0xffffffffffffffff

    table_ptr[5], table_ptr[4], table_ptr[1], table_ptr[0]=encry1120(table_ptr[5], table_ptr[4], table_ptr[1], table_ptr[0])
    table_ptr[7], table_ptr[6], table_ptr[3], table_ptr[2]=encry1120(table_ptr[7], table_ptr[6], table_ptr[3], table_ptr[2])
    table_ptr[1], table_ptr[0], table_ptr[5], table_ptr[4]=encry1120(table_ptr[1], table_ptr[0], table_ptr[5], table_ptr[4])
    table_ptr[3], table_ptr[2], table_ptr[7], table_ptr[6]=encry1120(table_ptr[3], table_ptr[2], table_ptr[7], table_ptr[6])

    return table_ptr



def encry1660(table):

    result=[]
    for i in table:
        result.append(i)

    for i in range(0,4):
        result=oneloop_encry1660(result)
    
    '''
    for i in result:
        print hex(i)

    for i,j in zip(result,target):
        print i==j
        if i!=j:
            print hex(i)
            print hex(j)
    '''

    return (result[0]+result[4]+result[8]+result[12])&0xffffffffffffffff

```

**sub17A0.py**

```python
#!/bin/python
from sub1120 import *


def encry17A0(size,flag):

    table_ptr=[]

    if flag==1:
        table_ptr=[\
        0x0CF0C0CBED5EDF48,
        0x1B37052812A528D2,
        0x213FAF142052526F,
        0x6B1147AEAE892205,
        0x063C052363821F70,
        0x5BA1C56E3EDEC22B,
        0xD91FB9753CA5209B,
        0x08233AB8F8F96C5F,
        0x1BE6D5D5FE4CCE2F,
        0x24093822299F31D0,
        0x33198A2E03707344,
        0x443F6A8885A308D3,
        0x5BD39E10CB0EF593,
        0x60ACF169B5F18A8C,
        0x7E5466CF34E90C6C,
        0x852821E638D01377]
    else:
        table_ptr=[\
        0x0CF0C0C5ED5EDF42,
        0x1B37052212A528CC,
        0x213FAF0E20525269,
        0x6B1147A8AE8921FF,
        0x8C18F014C18E087D,
        0xB96E8715ACFB7B08,
        0xD7647EE56CF29482,
        0xE0208CEA7FE3E5B1,
        0x1BE6D5D5FE4CCE2F,
        0x24093822299F31D0,
        0x33198A2E03707344,
        0x443F6A8885A308D3,
        0x5BD39E10CB0EF593,
        0x60ACF169B5F18A8C,
        0x7E5466CF34E90C6C,
        0x852821E638D01377]
    
    
    '''
    count= 4;
    do
      {
        v13 = *(table_ptr - 8);
        v14 = *(table_ptr - 4) + *table_ptr + *(_QWORD *)&v11[(_QWORD)table_ptr - 64];
        v15 = (unsigned int)(*((_DWORD *)table_ptr - 8) + *(_DWORD *)table_ptr + *(_DWORD *)&v11[(_QWORD)table_ptr - 64]);
        v16 = *(table_ptr - 8) >> 32;
        *(table_ptr - 4) = v14;
        ++table_ptr;
        *(table_ptr - 1) ^= v16 * v15;
        v17 = table_ptr[3];
        *(table_ptr - 9) = v13 + v17;
        table_ptr[3] = v17 ^ (unsigned int)(v13 + v17) * (v14 >> 32);
        --v12;
      }
      while ( v12 );
    '''
    
    Size=size
    i=8
    for j in range(4):
        temp1=table_ptr[i-8]
        temp2=(table_ptr[i-4]+table_ptr[i]+Size[i-8])&0xffffffffffffffff
        temp3=((table_ptr[i-4])+(table_ptr[i]&0xffffffff)+Size[i-8])&0xffffffff
        temp4=table_ptr[i-8]>>32
        table_ptr[i-4]=temp2
    
        i+=1
        table_ptr[i-1]^=(temp3*temp4)&0xffffffffffffffff
        temp5=table_ptr[i+3]
        table_ptr[i-9]=(temp1+temp5)&0xffffffffffffffff
        table_ptr[i+3]=(temp5^((temp1+temp5)&0xffffffff)*(temp2>>32))&0xffffffffffffffff
    
    
    
    table_ptr[5], table_ptr[4], table_ptr[1], table_ptr[0]=encry1120(table_ptr[5], table_ptr[4], table_ptr[1], table_ptr[0])
    table_ptr[7], table_ptr[6], table_ptr[3], table_ptr[2]=encry1120(table_ptr[7], table_ptr[6], table_ptr[3], table_ptr[2])
    table_ptr[1], table_ptr[0], table_ptr[5], table_ptr[4]=encry1120(table_ptr[1], table_ptr[0], table_ptr[5], table_ptr[4])
    table_ptr[3], table_ptr[2], table_ptr[7], table_ptr[6]=encry1120(table_ptr[3], table_ptr[2], table_ptr[7], table_ptr[6])
    
    
    return table_ptr

```

**main.py**

```python
#!/bin/python

import binascii
from sub17A0 import *
from sub1660 import *

size_hash=0xD31580A28DD8E6C4
flag_hash=0xAA302D9E67AAC4BA

gen_flag=lambda x:binascii.a2b_hex(hex(x)[2:][:-1])[::-1]
gen_flag2=lambda x:binascii.a2b_hex(hex(x)[2:])[::-1]

for i in range(0,255):

    table=encry17A0([i,0,0,0],0)
    myhash=encry1660(table)

    if myhash==size_hash:
        print 'get the size:'+str(i)
        

for f0 in range(0x30,0x3a):
    print f0
    for f1 in range(0x30,0x3a):
        for f2 in range(0x30,0x3a):
            for f3 in range(0x30,0x3a):
                for f4 in range(0x30,0x3a):
                    for f5 in range(0x30,0x3a):
                        for f6 in range(0x30,0x3a):
                            for f7 in range(0x30,0x3a):
                                for f8 in range(0x30,0x3a):
                                    for f9 in range(0x30,0x3a):
                                        num1=((((((((f7<<8)|f6)<<8|f5)<<8|f4)<<8|f3)<<8|f2)<<8|f1)<<8|f0)
                                        num2=(((f9<<8)|f9)<<8|f8)
                                        table=encry17A0([num1,0,num2,0],1)
                                        myhash=encry1660(table)
                                        if myhash==flag_hash:
                                            print 'get the flag'
                                            print 'hxb2018{'+gen_flag(num1)+gen_flag2(num2&0x00ffff)+'}'


# input:    01234567 89
# convert to  ====>
# input:    76543210 998

#num1=int(binascii.b2a_hex('76543210'),16)
#num2=int(binascii.b2a_hex('998'),16)

#table=encry17A0([num1,0,num2,0],1)
#myhash=encry1660(table)

#print hex(myhash)
 


```