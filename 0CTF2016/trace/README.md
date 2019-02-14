# 0CTF2016 trace

## Author: fanda

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>为了学习angr突然又跑来做逆向题。这是一个24800行的trace log，里面是mips汇编，像我这种头铁的人当然是直接分析。log虽然很长但是绝大多数都是函数执行的内部重复代码，其中0x400770是strlen函数，0x4007d0是strcpy函数，0x400858为一个quick sort函数。不懂mips的可以先看看这两篇资料复习一下：[寄存器](https://www.jianshu.com/p/79895392ecb2)，[指令集](https://www.jianshu.com/p/ac2c9e7b1d8f)。那么我们逐段解析一下这个log吧：</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先来看log开头的这部分：</font></br>

```mips
[INFO]004009f0                     lui r2, 0x41
[INFO]004009f4                lw r2, [r2+0xea0]
[INFO]004009f8                      move r4, r2
[INFO]004009fc                     jal 0x400770
[INFO]00400a00                      move r1, r1

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>猜测[0x410000+0xea0]的地址存着flag，然后作为0x400770函数的参数调用了strlen，这个move r1,r1的没什么意义，只是为了适应流水线结构出现的。看看函数的内部代码，同样可以看到函数开辟栈，保存参数等准备工作。随后就是内部逻辑：</font></br>

```mips
[INFO]00400770       addiu r29, r29, 0xffffffe8
[INFO]00400774               sw r30, [r29+0x14]
[INFO]00400778                    move r30, r29
[INFO]0040077c                sw r4, [r30+0x18]
[INFO]00400780                 sw r0, [r30+0x8]
[INFO]00400784                 lw r2, [r30+0x8]
[INFO]00400788                lw r3, [r30+0x18]
[INFO]0040078c                  addu r2, r3, r2
[INFO]00400790                  lb r2, [r2+0x0]
[INFO]00400794                bnez r2, 0x4007a8
[INFO]00400798                      move r1, r1
[INFO]004007a8                 lw r2, [r30+0x8]
[INFO]004007ac                addiu r2, r2, 0x1
[INFO]004007b0                 sw r2, [r30+0x8]
[INFO]004007b4                       j 0x400784
[INFO]004007b8                      move r1, r1
[INFO]00400784                 lw r2, [r30+0x8]
[INFO]00400788                lw r3, [r30+0x18]
[INFO]0040078c                  addu r2, r3, r2
[INFO]00400790                  lb r2, [r2+0x0]
[INFO]00400794                bnez r2, 0x4007a8
[INFO]00400798                      move r1, r1
...................
...................
[INFO]00400794                bnez r2, 0x4007a8
[INFO]00400798                      move r1, r1
[INFO]0040079c                 lw r2, [r30+0x8]
[INFO]004007a0                       j 0x4007bc
[INFO]004007a4                      move r1, r1
[INFO]004007bc                    move r29, r30
[INFO]004007c0               lw r30, [r29+0x14]
[INFO]004007c4             addiu r29, r29, 0x18
[INFO]004007c8                           jr r31
[INFO]004007cc                      move r1, r1
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>逻辑其实还是很容易分析的，对传入的字符串一个字节一个字节数数有没有到末尾，返回计数就是字符串长度了，很容易猜出来是strlen。bnez跳了26次所以flag长度为26。</font></br>

```mips
[INFO]00400a04               lw r28, [r30+0x10]
[INFO]00400a08                sw r2, [r30+0x2c]
[INFO]00400a0c                sw r0, [r30+0x18]
[INFO]00400a10                       j 0x400a4c
[INFO]00400a14                      move r1, r1
[INFO]00400a4c                lw r2, [r30+0x18]
[INFO]00400a50                slti r2, r2, 0x1a
[INFO]00400a54                bnez r2, 0x400a18
[INFO]00400a58                      move r1, r1
[INFO]00400a18                lw r2, [r30+0x18]
[INFO]00400a1c                andi r2, r2, 0xff
[INFO]00400a20               addiu r2, r2, 0x61
[INFO]00400a24                andi r2, r2, 0xff
[INFO]00400a28                 sll r3, r2, 0x18
[INFO]00400a2c                 sra r3, r3, 0x18
[INFO]00400a30              addiu r4, r30, 0x30
[INFO]00400a34                lw r2, [r30+0x18]
[INFO]00400a38                  addu r2, r4, r2
[INFO]00400a3c                  sb r3, [r2+0x0]
[INFO]00400a40                lw r2, [r30+0x18]
[INFO]00400a44                addiu r2, r2, 0x1
[INFO]00400a48                sw r2, [r30+0x18]
[INFO]00400a4c                lw r2, [r30+0x18]
[INFO]00400a50                slti r2, r2, 0x1a
...................
...................
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>strlen函数结束后在主函数里开始生成一串字符串，分析一下可以发现生成了"abcdef...ABCDEF....12345...{}"也就是完整的大小写加数字再加两个大括号这样一个长度为64的字符串。然后调用了strcpy(data+64,flag)，拼接成了长度为90的字符串：</font></br>

```mips
[INFO]00400b14                     lui r2, 0x41
[INFO]00400b18                lw r3, [r2+0xea0]
[INFO]00400b1c              addiu r2, r30, 0x30
[INFO]00400b20               addiu r2, r2, 0x40
[INFO]00400b24                      move r4, r2
[INFO]00400b28                      move r5, r3
[INFO]00400b2c                     jal 0x4007d0
[INFO]00400b30                      move r1, r1
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这是strcpy函数的逻辑，不难分析，逐字节复制直到第二个参数到末尾为止：</font></br>

```mips
[INFO]004007d0       addiu r29, r29, 0xffffffe8
[INFO]004007d4               sw r30, [r29+0x14]
[INFO]004007d8                    move r30, r29
[INFO]004007dc                sw r4, [r30+0x18]
[INFO]004007e0                sw r5, [r30+0x1c]
[INFO]004007e4                 sw r0, [r30+0x8]
[INFO]004007e8                       j 0x40081c
[INFO]004007ec                      move r1, r1
[INFO]0040081c                 lw r2, [r30+0x8]
[INFO]00400820                lw r3, [r30+0x1c]
[INFO]00400824                  addu r2, r3, r2
[INFO]00400828                  lb r2, [r2+0x0]
[INFO]0040082c                bnez r2, 0x4007f0
[INFO]00400830                      move r1, r1
[INFO]004007f0                 lw r2, [r30+0x8]
[INFO]004007f4                lw r3, [r30+0x18]
[INFO]004007f8                  addu r2, r3, r2
[INFO]004007fc                 lw r3, [r30+0x8]
[INFO]00400800                lw r4, [r30+0x1c]
[INFO]00400804                  addu r3, r4, r3
[INFO]00400808                  lb r3, [r3+0x0]
[INFO]0040080c                  sb r3, [r2+0x0]
[INFO]00400810                 lw r2, [r30+0x8]
[INFO]00400814                addiu r2, r2, 0x1
[INFO]00400818                 sw r2, [r30+0x8]
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>strcpy结束之后对这段长度90字节的字符串进行quick sort，qsort(data,strlen(data))：</font></br>

```mips
[INFO]00400b48               lw r28, [r30+0x10]
[INFO]00400b4c                      move r3, r2
[INFO]00400b50              addiu r2, r30, 0x30
[INFO]00400b54                      move r4, r2
[INFO]00400b58                      move r5, r3
[INFO]00400b5c                     jal 0x400858
[INFO]00400b60                      move r1, r1
[INFO]00400858       addiu r29, r29, 0xffffffd0
[INFO]0040085c               sw r31, [r29+0x2c]
[INFO]00400860               sw r30, [r29+0x28]
[INFO]00400864                    move r30, r29
[INFO]00400868                sw r4, [r30+0x30]
[INFO]0040086c                sw r5, [r30+0x34]
[INFO]00400870                lw r2, [r30+0x34]
[INFO]00400874                 slti r2, r2, 0x2
[INFO]00400878                beqz r2, 0x400888
[INFO]0040087c                      move r1, r1
[INFO]00400888                lw r2, [r30+0x30]
[INFO]0040088c                 lbu r2, [r2+0x0]
[INFO]00400890                sb r2, [r30+0x20]
[INFO]00400894                addiu r2, r0, 0x1
[INFO]00400898                sw r2, [r30+0x18]
[INFO]0040089c                addiu r2, r0, 0x1
[INFO]004008a0                sw r2, [r30+0x1c]
[INFO]004008a4                       j 0x40092c
[INFO]004008a8                      move r1, r1
[INFO]0040092c                lw r3, [r30+0x1c]
[INFO]00400930                lw r2, [r30+0x34]
[INFO]00400934                   slt r2, r3, r2
[INFO]00400938                bnez r2, 0x4008ac
[INFO]0040093c                      move r1, r1
[INFO]004008ac                lw r2, [r30+0x1c]
[INFO]004008b0                lw r3, [r30+0x30]
[INFO]004008b4                  addu r2, r3, r2
[INFO]004008b8                  lb r2, [r2+0x0]
[INFO]004008bc                lb r3, [r30+0x20]
[INFO]004008c0                   slt r2, r2, r3
[INFO]004008c4                beqz r2, 0x400920
[INFO]004008c8                      move r1, r1
[INFO]004008cc                lw r2, [r30+0x18]
[INFO]004008d0                lw r3, [r30+0x30]
[INFO]004008d4                  addu r2, r3, r2
[INFO]004008d8                 lbu r2, [r2+0x0]
[INFO]004008dc                sb r2, [r30+0x21]
[INFO]004008e0                lw r2, [r30+0x18]
[INFO]004008e4                lw r3, [r30+0x30]
[INFO]004008e8                  addu r2, r3, r2
[INFO]004008ec                lw r3, [r30+0x1c]
[INFO]004008f0                lw r4, [r30+0x30]
[INFO]004008f4                  addu r3, r4, r3
[INFO]004008f8                  lb r3, [r3+0x0]
[INFO]004008fc                  sb r3, [r2+0x0]
[INFO]00400900                lw r2, [r30+0x1c]
[INFO]00400904                lw r3, [r30+0x30]
[INFO]00400908                  addu r2, r3, r2
[INFO]0040090c               lbu r3, [r30+0x21]
[INFO]00400910                  sb r3, [r2+0x0]
[INFO]00400914                lw r2, [r30+0x18]
[INFO]00400918                addiu r2, r2, 0x1
[INFO]0040091c                sw r2, [r30+0x18]
[INFO]00400920                lw r2, [r30+0x1c]
[INFO]00400924                addiu r2, r2, 0x1
[INFO]00400928                sw r2, [r30+0x1c]
..................
..................
[INFO]00400940                lw r2, [r30+0x18]
[INFO]00400944         addiu r2, r2, 0xffffffff
[INFO]00400948                lw r3, [r30+0x30]
[INFO]0040094c                  addu r2, r3, r2
[INFO]00400950                 lbu r2, [r2+0x0]
[INFO]00400954                sb r2, [r30+0x21]
[INFO]00400958                lw r2, [r30+0x18]
[INFO]0040095c         addiu r2, r2, 0xffffffff
[INFO]00400960                lw r3, [r30+0x30]
[INFO]00400964                  addu r2, r3, r2
[INFO]00400968                lw r3, [r30+0x30]
[INFO]0040096c                  lb r3, [r3+0x0]
[INFO]00400970                  sb r3, [r2+0x0]
[INFO]00400974                lw r2, [r30+0x30]
[INFO]00400978               lbu r3, [r30+0x21]
[INFO]0040097c                  sb r3, [r2+0x0]
[INFO]00400980                lw r2, [r30+0x18]
[INFO]00400984         addiu r2, r2, 0xffffffff
[INFO]00400988                lw r4, [r30+0x30]
[INFO]0040098c                      move r5, r2
[INFO]00400990                     jal 0x400858
[INFO]00400994                      move r1, r1
..................
..................
[INFO]004009cc                           jr r31
[INFO]004009d0                      move r1, r1
[INFO]00400998                lw r2, [r30+0x18]
[INFO]0040099c                lw r3, [r30+0x30]
[INFO]004009a0                  addu r4, r3, r2
[INFO]004009a4                lw r3, [r30+0x34]
[INFO]004009a8                lw r2, [r30+0x18]
[INFO]004009ac                  subu r2, r3, r2
[INFO]004009b0                      move r5, r2
[INFO]004009b4                     jal 0x400858
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>qsort的代码看上去有些多啊，解释就不在这说了，但其实也不难，就是内部有个递归调用分析起来比较复杂。qsort函数全部执行完毕之后flag就散布在整个字符串里了，flag就是从最后的判断中推算出来的：</font></br>

```mips
[INFO]00400b64               lw r28, [r30+0x10]
[INFO]00400b68              addiu r2, r30, 0x30
[INFO]00400b6c                      move r4, r2
[INFO]00400b70                     jal 0x400770
[INFO]00400b74                      move r1, r1
...................
...................
[INFO]004007c8                           jr r31
[INFO]004007cc                      move r1, r1
[INFO]00400b78               lw r28, [r30+0x10]
[INFO]00400b7c                sw r2, [r30+0x2c]
[INFO]00400b80                sw r0, [r30+0x24]
[INFO]00400b84                sw r0, [r30+0x28]
[INFO]00400b88                       j 0x400bd4
[INFO]00400b8c                      move r1, r1
[INFO]00400bd4                lw r2, [r30+0x2c]
[INFO]00400bd8         addiu r3, r2, 0xffffffff
[INFO]00400bdc                lw r2, [r30+0x28]
[INFO]00400be0                   slt r2, r2, r3
[INFO]00400be4                bnez r2, 0x400b90
[INFO]00400be8                      move r1, r1
[INFO]00400b90              addiu r3, r30, 0x30
[INFO]00400b94                lw r2, [r30+0x28]
[INFO]00400b98                  addu r2, r3, r2
[INFO]00400b9c                  lb r3, [r2+0x0]
[INFO]00400ba0                lw r2, [r30+0x28]
[INFO]00400ba4                addiu r2, r2, 0x1
[INFO]00400ba8              addiu r4, r30, 0x30
[INFO]00400bac                  addu r2, r4, r2
[INFO]00400bb0                  lb r2, [r2+0x0]
[INFO]00400bb4             beq r3, r2, 0x400bc8
[INFO]00400bb8                      move r1, r1
[INFO]00400bbc                lw r2, [r30+0x24]
[INFO]00400bc0                addiu r2, r2, 0x1
[INFO]00400bc4                sw r2, [r30+0x24]
[INFO]00400bc8                lw r2, [r30+0x28]
[INFO]00400bcc                addiu r2, r2, 0x1
[INFO]00400bd0                sw r2, [r30+0x28]
[INFO]00400bd4                lw r2, [r30+0x2c]
[INFO]00400bd8         addiu r3, r2, 0xffffffff
[INFO]00400bdc                lw r2, [r30+0x28]
[INFO]00400be0                   slt r2, r2, r3
[INFO]00400be4                bnez r2, 0x400b90
[INFO]00400be8                      move r1, r1
..................
..................
[INFO]00400be4                bnez r2, 0x400b90
[INFO]00400be8                      move r1, r1
[INFO]00400bec                lw r3, [r30+0x24]
[INFO]00400bf0               addiu r2, r0, 0x3f
[INFO]00400bf4             beq r3, r2, 0x400c10
[INFO]00400bf8                      move r1, r1
[INFO]00400c10              addiu r2, r30, 0x30
[INFO]00400c14                      move r4, r2
[INFO]00400c18          lw r2, [r28+0xffff8034]
[INFO]00400c1c                     move r25, r2
[INFO]00400c20                         jalr r25
[INFO]00400c24                      move r1, r1
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所有的代码都分析完了，接下来就是用C重写的近似逻辑：</font></br>

```C
void qsort(char* data, int len)
{
	char t;
	if(len<2)
		return;

	int j=1;
	for(int i=1;i<len;++i)
		if(data[i] < data[0])
		{
			t=data[j];
			data[j]=data[i];
			data[i]=t;
			j++;
		}

	t=data[j-1];
	data[j-1]=data[0];
	data[0]=t;

	qsort(data,j-1);
	qsort(data+j,len-j);
}

int main() 
{
	char data[91] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}";

	strlen(flag);
	strcpy(data+64,flag);
	qsort(data,strlen(data));

	int s=0;
	for(int i=0;i<strlen(data)-1;++i)
		if(data[i]!=data[i+1])
			s++;
	// s==63
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后用python解析log模拟行为就能推测出flag了，我用了某个大佬的脚本然后改了一下写了完整版的solve.py：</font></br>

```python
import string
table = list(string.ascii_letters + string.digits + '{}') + range(26)
f = open('./trace_8339a701aae26588966ad9efa0815a0a.log')
def qsort(s, begin, end):
    t = True
    i, j= begin + 1, begin + 1
    for l in f:
        if 'jr r31' in l:
            return
        elif '004008ac' in l:
            t = True
        elif '004008cc' in l:
            t = False
            s[i], s[j] = s[j], s[i]
            j, i = j+1, i+1
        elif '00400920' in l and t:
            i += 1
        elif '00400940' in l:
            s[j-1], s[begin] = s[begin], s[j-1]
            qsort(s, begin, j-1)
        elif '00400998' in l:
            qsort(s, j, end)

for i in f:
    if 'jal 0x400858' in i:
        break

qsort(table, 0, len(table))
#print table

table_bak=[]
theSet=[]
for i in table:
    if type(i)!=int:
        table_bak.append(i)
    else:
        theSet.append(i)

f.seek(0)
flag=''
t=True
s=0

for i in f:
    if '00400bc0' in i:
        s+=1
        t=False
    elif '00400bc8' in i:
        if t:
            flag+=table_bak[s]
        t=True

print flag

Flag=[None]*26
for i,j in zip(theSet,flag):
    Flag[i]=j
print ''.join(Flag)
```

