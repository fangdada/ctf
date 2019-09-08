### z3-solver多解的遍历

&emsp;&emsp;<font size=2>在周末的时候去2019护网杯做了一题re_quiz_middle，但是这篇文章不是writeup！我做这题的思路失败了，但也因此发现z3-solver这东西玄乎的一些东西。写这一篇文章谨以记录这次踩的坑，也不要过分依赖符号工具。</font></br>

&emsp;&emsp;<font size=2>在题目内容之前，首先来看一个小例子，这是一个多解的情况：</font></br>

```python
a = Int('a')
b = Int('b')

s = Solver()
s.add(1 <= a)
s.add(a <= 20)
s.add(1 <= b)
s.add(b <= 20)
s.add(a >= 2*b)
```

&emsp;&emsp;<font size=2>这一个约束我们很容易的就能看出来这是多解的，如果z3-solver只允许出现唯一解的话`s.check()`应当返回`unsat`，但是这里是`sat`的，我们来看看`s.model()`返回的解：</font></br>

```python
In [1]: from z3 import *

In [2]: a = Int('a')
   ...: b = Int('b')
   ...:
   ...: s = Solver()
   ...: s.add(1 <= a)
   ...: s.add(a <= 20)
   ...: s.add(1 <= b)
   ...: s.add(b <= 20)
   ...: s.add(a >= 2*b)

In [3]: if(s.check()==sat):
   ...:     print(s.model())
   ...:
[b = 1, a = 2]

In [4]:
```

&emsp;&emsp;<font size=2>这可以说是最小的一个解了，但是这是一个多解的情况，如何遍历呢？对两个未知数我们可以这样遍历：</font></br>

```python
In [4]: while(s.check()==sat):
   ...:     model=s.model()
   ...:     print(model)
   ...:     s.add(Or(model[a]!=a,model[b]!=b))
   ...:
[b = 1, a = 2]
[b = 2, a = 4]
[b = 1, a = 3]
[b = 3, a = 6]
[b = 4, a = 8]
[b = 5, a = 10]
[b = 3, a = 7]
...........
[b = 7, a = 16]
[b = 7, a = 14]
[b = 5, a = 18]
[b = 5, a = 17]
[b = 5, a = 16]
[b = 2, a = 20]
[b = 1, a = 20]
[b = 8, a = 20]
[b = 9, a = 20]
```

&emsp;&emsp;<font size=2>省略了一些，一共输出了100个解，刚好是所有满足条件的解。我们改进一下脚本，由此可以引出迭代任意球未知数的所有解的方式：</font></br>

```python
from z3 import *

def RecurOr(flags,models,pos=0):
    if(pos<len(flags)-1):
        return Or(models[flags[pos]]!=flags[pos],RecurOr(flags,models,pos+1))
    else:
        return Or(models[flags[pos]]!=flags[pos])

t=[]
t.append(Int('a'))
t.append(Int('b'))

s = Solver()
s.add(1 <= t[0])
s.add(t[0] <= 20)
s.add(1 <= t[1])
s.add(t[1] <= 20)
s.add(t[0] >= 2*t[1])

while(s.check()==sat):
    model=s.model()
    print(model)
    s.add(RecurOr(t,model))
```

---

### 解re_quiz_middle失败

&emsp;&emsp;<font size=2>先用IDA看了一下，发现符号表被去除了，连基本的printf函数都看不到了，因此改用x64dbg进行动态调试（不用OD是因为插件太多了，总感觉逆起来不痛快），接收字符串和长度判断见如下图：</font></br>

![read函数](https://raw.githubusercontent.com/fangdada/ctf/master/护网杯2019/screenshot/read函数.png)

&emsp;&emsp;<font size=2>这里一个`cmp dword ptr ss:[ebp-48],15`判断了是否输入了0x15个字节，且在后来还验证了输入的格式必须为`flag{xxxxx}`这样。然后如下函数：</font></br>

![rand函数](https://raw.githubusercontent.com/fangdada/ctf/master/护网杯2019/screenshot/rand函数.png)

&emsp;&emsp;<font size=2>其实是一个`rand()`函数，先以我们输入的某三个字节用作`srand()`的种子，然后后续用`rand()`不断获取随机值来做hash运算。代码还原后如下：</font></br>

```python
def hashbuf(n):
    result=n*0x343FD
    result+=0x269EC3
    result&=0xFFFFFFFF
    return result
def hash(n):
    result=(n>>16)&0x7FFF
    return result

key=0x313131		# 我们输入的某三个字节
for i in range(12):
    result=0
    if key1==0:
        key1=hashbuf(key)
    else:
        key1=hashbuf(key1)
    hash1=hash(key1)    #rand()
    #print(hex(hash1))
    for j in range(12):
        n=hash1&0xFF
        hash1>>=1
        if(n&1):
            result+=flag[j]
        else:
            result^=flag[j]
    #print(hex(result))
```

&emsp;&emsp;<font size=2>12次循环最后返回的result就是一数组密文，最后跟密文比较，正确了就会输出`Wonderful`，那我就姑且相信这个就是正确的flag验证方式吧，毕竟就算是假的flag也跟我想表达的没关系，这篇的重点是z3-solver的错解和多解。</font></br>

&emsp;&emsp;<font size=2>然后我的思路是：**3字节key+12字节的输入，这两个东西我们全都未知；假设我们3字节的key已知，`rand()`每次返回的随机数也就已知，也就知道了上面`if(n&1)`每一次的判断结果，知道了和输入的每个字节相加或异或的顺序；因此我们可以爆破key，然后将输入用符号代替求约束解，如果解存在就意味着这个key是有效的，我们就可以得知这个key应该就是正确的key，以此反推flag。**，然后就有了如下爆破脚本：</font></br>

```python
from z3 import *
import threading
import time

# flag密文
flag_array=[0x215,0x111,0x101,0x167,0x3E7,0x235,0x2DB,0x139,0x2E1,0x1FD,0x34F,0x1ED]

key=0x313131

def hashbuf(n):
    result=n*0x343FD
    result+=0x269EC3
    result&=0xFFFFFFFF
    return result
def hash(n):
    result=(n>>16)&0x7FFF
    return result
def Proceding():
    global key
    while(1):
        time.sleep(3)
        print("now:"+hex(key))

def RecurOr(flags,models,pos=0):
    if(pos<len(flags)-1):
        return Or(models[flags[pos]]!=flags[pos],RecurOr(flags,models,pos+1))
    else:
        return Or(models[flags[pos]]!=flags[pos])
f=open("rehash.result","a")

flag=[]
for i in range(12):
    flag.append(BitVec(i,7))

t=threading.Thread(target=Proceding)
t.daemon=True
t.start()
while(key <= 0x7A7A7A):
    s=Solver()
    key1=0
    if(key&0xFF == 0x3a):
        key=((key&0xFFFF00)|0x41)
    if(key&0xFF == 0x5b):
        key=((key&0xFFFF00)|0x61)
    if(key&0xFF == 0x7b):
        key=(key+0x100)&0xFFFF30
    if(key&0xFF00 == 0x3a00):
        key=((key&0xFF00FF)|0x4100)
    if(key&0xFF00 == 0x5b00):
        key=((key&0xFF00FF)|0x6100)
    if(key&0xFF00 == 0x7b00):
        key=(key+0x10000)&0xFF3030
    if(key&0xFF0000 == 0x3a0000):
        key=((key&0xFFFF)|0x410000)
    if(key&0xFF0000 == 0x5b0000):
        key=((key&0xFFFF)|0x610000)
    #srand(key1)
    for i in range(12):
        result=0
        if key1==0:
            key1=hashbuf(key)
        else:
            key1=hashbuf(key1)
        hash1=hash(key1)    #rand()
        #print(hex(hash1))
        for j in range(12):
            n=hash1&0xFF
            hash1>>=1
            if(n&1):
                result+=flag[j]
            else:
                result^=flag[j]
        #print(hex(result))
        s.add(result==flag_array[i])
    #for i in range(12):
    #    s.add(And(flag[i]>=0x30,flag[i]<=0x39))
    while(s.check()==sat):
        output=[]
        model=s.model()
        print("\n**Notice**: key is:"+hex(key)+'\n')
        for j in range(12):
            print(hex(model[flag[j]].as_long())+" ")
        for j in range(12):
            output.append(chr(model[flag[j]].as_long()))
        f.write(hex(key)+"".join(output)+'\n')
        #s.add(RecurOr(flag,model))
    key=key+1
f.close()
```

&emsp;&emsp;<font size=2>然后就开始漫漫爆破了，结果令我吃惊，出现了数量非常多的解！我盯着看了`s.add(result==flag_array[i])`很久，打算验证一下这些输出，于是我取出了其中一个flag解：`key：30606c。flag:3363331402670b2b4d49080d`。然后代入了题，在`rand()`处下断把输入通过二进制编辑改为了以上一个解，结果却跟目标密文大不相同：</font></br>

![反代](https://raw.githubusercontent.com/fangdada/ctf/master/护网杯2019/screenshot/反代.png)

```python
flag_array=[0x215,0x111,0x101,0x167,0x3E7,0x235,0x2DB,0x139,0x2E1,0x1FD,0x34F,0x1ED]
#我们的输出：
output_array=[0x17D,0xCD,0xD9,0x191,0x1CB,0x1D9,0x161,0x63,0x13B,0x1CB,0x171,0xED]
```

&emsp;&emsp;<font size=2>可以看到有很大的差异。接下来我们证明一下不是我脚本的问题，以自己的key和flag为例（全1），首先对题目程序输入`flag{111111111111111}`，然后运行断在cmp比较flag处，然后提取出hash结果为：</font></br>

![提取1](https://raw.githubusercontent.com/fangdada/ctf/master/护网杯2019/screenshot/提取1.png)

```python
flag_array=[0x104,0x84,0x84,0x0,0x1A6,0x1CC,0x1CC,0x148,0x1C8,0xE2,0xE2,0x126]         #'111'
```

&emsp;&emsp;<font size=2>脚本注释掉符号，然后改为输出result：</font></br>

```python
from z3 import *
import threading
import time

flag_array=[0x104,0x84,0x84,0x0,0x1A6,0x1CC,0x1CC,0x148,0x1C8,0xE2,0xE2,0x126]         #'111'

key=0x313131

def hashbuf(n):
    result=n*0x343FD
    result+=0x269EC3
    result&=0xFFFFFFFF
    return result
def hash(n):
    result=(n>>16)&0x7FFF
    return result

#flag=[]
#for i in range(12):
#    flag.append(BitVec(i,7))
flag="111111111111"

while(key <= 0x7A7A7A):
    s=Solver()
    key1=0
    #srand(key1)
    for i in range(12):
        result=0
        if key1==0:
            key1=hashbuf(key)
        else:
            key1=hashbuf(key1)
        hash1=hash(key1)    #rand()
        #print(hex(hash1))
        for j in range(12):
            n=hash1&0xFF
            hash1>>=1
            if(n&1):
                result+=ord(flag[j])
            else:
                result^=ord(flag[j])
        print(hex(result))
    exit(0)
```

&emsp;&emsp;<font size=2>运行结果：</font></br>

```bash
➜  ~ python rehash.py
0x104
0x84
0x84
0x0
0x1a6
0x1cc
0x1cc
0x148
0x1c8
0xe2
0xe2
0x126
➜  ~
```

&emsp;&emsp;<font size=2>康康，没问题吧？逻辑是应该没问题的，然后把脚本改回去用符号求解一下：</font></br>

```python
from z3 import *
import threading
import time

flag_array=[0x104,0x84,0x84,0x0,0x1A6,0x1CC,0x1CC,0x148,0x1C8,0xE2,0xE2,0x126]         #'111'

key=0x313131

def hashbuf(n):
    result=n*0x343FD
    result+=0x269EC3
    result&=0xFFFFFFFF
    return result
def hash(n):
    result=(n>>16)&0x7FFF
    return result
def Proceding():
    global key
    while(1):
        time.sleep(3)
        print("now:"+hex(key))

flag=[]
for i in range(12):
    flag.append(BitVec(i,7))

t=threading.Thread(target=Proceding)
t.daemon=True
t.start()
while(key <= 0x7A7A7A):
    s=Solver()
    key1=0
    for i in range(12):
        result=0
        if key1==0:
            key1=hashbuf(key)
        else:
            key1=hashbuf(key1)
        hash1=hash(key1)    #rand()
        #print(hex(hash1))
        for j in range(12):
            n=hash1&0xFF
            hash1>>=1
            if(n&1):
                result+=flag[j]
            else:
                result^=flag[j]
        s.add(result==flag_array[i])
    #for i in range(12):
    #    s.add(And(flag[i]>=0x30,flag[i]<=0x39))
    if(s.check()==sat):
        model=s.model()
        for j in range(12):
            print(hex(model[flag[j]].as_long())+" ")
    exit(0)
```

&emsp;&emsp;<font size=2>在注释掉`s.add(And(flag[i]>=0x30,flag[i]<=0x39))`的情况下给出的解如下：</font></br>

```bash
➜  ~ python rehash.py
0x6d
0x3f
0x67
0x69
0x31
0x69
0x39
0x75
0x31
0x2d
0x2d
0x75
➜  ~
```

&emsp;&emsp;<font size=2>把上面这个解再次代入到题目里面，给出的结果如下：</font></br>

![修改输入](https://raw.githubusercontent.com/fangdada/ctf/master/护网杯2019/screenshot/修改输入.png)

```python
flag_array=[0x104,0x84,0x84,0x0,0x1A6,0x1CC,0x1CC,0x148,0x1C8,0xE2,0xE2,0x126]
#我们的输出：
output_array=[0x204,0x104,0x104,0x80,0x226,0x2cc,0x2cc,0x1c8,0x348,0x2E2,0x1E2,0x226]
```

&emsp;&emsp;<font size=2>竟然不相同！按照之前的验证脚本逻辑应该是没问题的吧，如果还不能证明z3-solver有问题的话，来看看把`s.add(And(flag[i]>=0x30,flag[i]<=0x39))`这个循环的注释去掉，增加数字的约束条件后输出如下：</font></br>

```bash
➜  ~ python rehash.py
0x31
0x31
0x31
0x31
0x31
0x31
0x31
0x31
0x31
0x31
0x31
0x31
➜  ~
```

&emsp;&emsp;<font size=2>一点问题都没有，那么这是不是说明“111111111111”的解包含在z3-solver的多解中呢？答案是：也许是，也许不是。如果你注释约束，用之前遍历多解的函数运行如下脚本的话会发现有无数解不停被输出：</font></br>

```python
from z3 import *
import threading
import time

flag_array=[0x104,0x84,0x84,0x0,0x1A6,0x1CC,0x1CC,0x148,0x1C8,0xE2,0xE2,0x126]         #'111'

key=0x313131

def hashbuf(n):
    result=n*0x343FD
    result+=0x269EC3
    result&=0xFFFFFFFF
    return result
def hash(n):
    result=(n>>16)&0x7FFF
    return result
def Proceding():
    global key
    while(1):
        time.sleep(3)
        print("now:"+hex(key))

def RecurOr(flags,models,pos=0):
    if(pos<len(flags)-1):
        return Or(models[flags[pos]]!=flags[pos],RecurOr(flags,models,pos+1))
    else:
        return Or(models[flags[pos]]!=flags[pos])

flag=[]
for i in range(12):
    flag.append(BitVec(i,7))

while(key <= 0x7A7A7A):
    s=Solver()
    key1=0
    #srand(key1)
    for i in range(12):
        result=0
        if key1==0:
            key1=hashbuf(key)
        else:
            key1=hashbuf(key1)
        hash1=hash(key1)    #rand()
        #print(hex(hash1))
        for j in range(12):
            n=hash1&0xFF
            hash1>>=1
            if(n&1):
                result+=flag[j]
            else:
                result^=flag[j]
        #print(hex(result))
        s.add(result==flag_array[i])
    #for i in range(12):
    #    s.add(And(flag[i]>=0x30,flag[i]<=0x39))

    while(s.check()==sat):
        model=s.model()
        print("\n**Notice**: key is:"+hex(key)+'\n')
        for j in range(12):
            print(hex(model[flag[j]].as_long())+" ")
        s.add(RecurOr(flag,model))
    key=key+1
    exit(0)
```

&emsp;&emsp;<font size=2>控制流不会到达`exit(0)`。综上分析，应该是我的解题思路的问题，也许这题并不能用符号来爆破。</font></br>

&emsp;&emsp;<font size=2>这也是我第一次遇到z3-solver解题出意外的情况，解出来的值反代回去竟然不符合约束条件。不知道是不是跟多解有联系，总之也许不能过于相信工具吧Orz。</font></br>
