# QCTF2018 babyre
## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>这题就比较坑了，程序打开来吓了一跳，这正是我最怕的类型的题目，不知道啥语言写的，程序打开来乱七八糟。看了官方wp后得知是rust写的，于是就搭了个rust环境写了个hello，emmmm我连hello world都看不懂了？折腾了一下只知道了怎么找真正的main函数，好吧，那就动态调试咯。</br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>IDA远程调试Linux程序，启动！在__libc_start_main前下断到main函数，然后反汇编是这样的：</br>

```arm
; int __cdecl main(int, char **, char **)
main proc near

var_8= qword ptr -8

; __unwind {
push    rax
lea     rax, sub_A110
movsxd  rcx, edi
mov     rdi, rax
mov     [rsp+8+var_8], rsi
mov     rsi, rcx
mov     rdx, [rsp+8+var_8]
call    sub_CB50
mov     r8d, eax
mov     eax, r8d
pop     rcx
retn
; } // starts at A500
main endp
```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>看到那个lea没？后面那个sub_A110才是rust真正的main函数，反正我太菜了找到了也看不懂:)</br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>动态调试的时候直接在那下断到main函数，F8往下走，突然不动了等待输入，然后根据下文的cmp rax,20h得知输入32个字符，我输入了0123456789abc...等32个。然后根据栈找到输入的缓冲区处下硬件断点，直接F9跑，发现在另一块内存里有备份，再到备份处也下断，一共备份了三次。再F9跑了一次发现进入了加密部分。嗯，终究还是套路。</br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>加密部分反汇编我就不贴了，就贴一下每次F9跑完加密后的内存状况吧，一共加密了三轮：</br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>第一轮加密对四个字符一组进行了组内置换：</br>

```hex
00007F9AAA21F050  02 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00007F9AAA21F060  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  0123456789abcdef
00007F9AAA21F070  67 68 69 6A 6B 6C 6D 6E  6F 70 71 72 73 74 75 76  ghijklmnopqrstuv
00007F9AAA21F080  32 30 33 31 36 34 37 35  61 38 62 39 65 63 66 64  20316475a8b9ecfd
00007F9AAA21F090  69 67 6A 68 6D 6B 6E 6C  71 6F 72 70 75 73 76 74  igjhmknlqorpusvt
00007F9AAA21F0A0  00 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  .123456789abcdef
00007F9AAA21F0B0  67 68 69 6A 6B 6C 6D 6E  6F 70 71 72 73 74 75 76  ghijklmnopqrstuv
00007F9AAA21F0C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>第二轮加密对四个字符一组的组里的每个字符各加了一个不同的常数：</br>

```hex
00007F9AAA21F050  02 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00007F9AAA21F060  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  0123456789abcdef
00007F9AAA21F070  67 68 69 6A 6B 6C 6D 6E  6F 70 71 72 73 74 75 76  ghijklmnopqrstuv
00007F9AAA21F080  00 30 33 31 36 34 37 35  61 38 62 39 65 63 66 64  .0316475a8b9ecfd
00007F9AAA21F090  69 67 6A 68 6D 6B 6E 6C  71 6F 72 70 75 73 76 74  igjhmknlqorpusvt
00007F9AAA21F0A0  39 42 8B B2 3D 46 8F B6  68 4A BA BA 6C 75 BE E5  9B..=F..hJ..lu..
00007F9AAA21F0B0  70 79 C2 E9 74 7D C6 ED  78 81 CA F1 7C 85 CE F5  py..t}..x...|...
00007F9AAA21F0C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>第三次加密对四个字符一组的组里的每个字符各进行了一次可逆的位变换：</br>

```hex
00007F9AAA21F050  02 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00007F9AAA21F060  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  0123456789abcdef
00007F9AAA21F070  67 68 69 6A 6B 6C 6D 6E  6F 70 71 72 73 74 75 76  ghijklmnopqrstuv
00007F9AAA21F080  C9 90 17 2B E9 91 1F 6B  43 92 75 AB 63 5D 7D 5E  ɐ .+...kC.u.c]}^
00007F9AAA21F090  83 5E 85 9E A3 5F 8D DE  C3 60 95 1F E3 61 9D 5F  .^..._...`....._
00007F9AAA21F0A0  DA 42 8B B2 3D 46 8F B6  68 4A BA BA 6C 75 BE E5  ....=F..hJ..lu..
00007F9AAA21F0B0  70 79 C2 E9 74 7D C6 ED  78 81 CA F1 7C 85 CE F5  py..t}..x...|...
00007F9AAA21F0C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>最后对加密完的数据跟密文对比，常规套路。</br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>所以摸清了加密的规则就好办了，加密可逆那就直接写脚本对key逆运算得出flag：</br>

脚本
======

```python
#encoding:utf-8

key="\xDA\xD8\x3D\x4C\xE3\x63\x97\x3D\
\xC1\x91\x97\x0E\xE3\x5C\x8D\x7E\
\x5B\x91\x6F\xFE\xDB\xD0\x17\xFE\
\xD3\x21\x99\x4B\x73\xD0\xAB\xFE"


def encrypt(input):
  output1=''
  output2=''
  output3=''
  for i in range(0,len(input),4):
    output1+=input[i+2]+input[i]+input[i+3]+input[i+1]
  
  for i in range(0,len(output1),4):
    output2+=chr(ord(output1[i])+0x7)
    output2+=chr(ord(output1[i+1])+0x12)
    output2+=chr(ord(output1[i+2])+0x58)
    output2+=chr(ord(output1[i+3])+0x81)

  for i in range(0,len(output2),4):
    output3+=chr((ord(output2[i])>>5)|((ord(output2[i])<<3)&0xff))
    output3+=chr((ord(output2[i+1])>>2)|((ord(output2[i+1])<<6)&0xff))
    output3+=chr((ord(output2[i+2])>>7)|((ord(output2[i+2])<<1)&0xff))
    output3+=chr((ord(output2[i+3])>>4)|((ord(output2[i+3])<<4)&0xff))
  

  return output3



def decrypt(input):
  output1=''
  output2=''
  output3=''

  for i in range(0,len(input),4):
    output1+=chr(((ord(input[i])<<5)&0xff)|(ord(input[i])>>3))
    output1+=chr(((ord(input[i+1])<<2)&0xff)|(ord(input[i+1])>>6))
    output1+=chr(((ord(input[i+2])<<7)&0xff)|(ord(input[i+2])>>1))
    output1+=chr(((ord(input[i+3])<<4)&0xff)|(ord(input[i+3])>>4))

  for i in range(0,len(output1),4):
    output2+=chr(ord(output1[i])-0x7)
    output2+=chr(ord(output1[i+1])-0x12)
    output2+=chr(ord(output1[i+2])-0x58)
    output2+=chr(ord(output1[i+3])-0x81)
    
  for i in range(0,len(output2),4):
    output3+=output2[i+1]+output2[i+3]+output2[i]+output2[i+2]

  return output3



if __name__ == '__main__':
  
  input='0123456789abcdefghijklmnopqrstuv'
  output=encrypt(input)

  flag=decrypt(key)
  print flag

  #QCTF{Rus4_1s_fun4nd_1nt3r3st1ng}
```