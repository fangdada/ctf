# 网鼎杯第一场 src
## Author: 文火

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>这道题事后看了别人的wp才知道还能有这种骚操作。。</br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>不知道这个程序什么语言写的，函数名啥的都很长，直接运行会给出这样的字符串：</br>

```
welcome, here is your identification, please keep it in your pocket: 4b404c4b5648725b445845734c735949405c414d5949725c45495a51

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>flag一般都已"qctf"，"QCTF"，"flag"开头，所以先用异或试探一下：</br>

```python
import binascii

key='4b404c4b5648725b445845734c735949405c414d5949725c45495a51'
guess='qctfQCTFflag'

key=binascii.a2b_hex(key)

for n in range(0,3):
  for i,j in zip(key[:4],guess[n*4:(n+1)*4]):
    print ord(i)^ord(j),
  print ''

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>然后我们得到:</br>

```
58 35 56 45 
26 3 24 13 
45 44 45 44
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>也就是说猜测"flag"的时候有一个类似规律性的44，45的异或，然后写了一个脚本：</br>

```python
import binascii

key='4b404c4b5648725b445845734c735949405c414d5949725c45495a51'
guess='qctfQCTFflag'

key=binascii.a2b_hex(key)

for n in range(0,3):
  for i,j in zip(key[:4],guess[n*4:(n+1)*4]):
    print ord(i)^ord(j),
  print ''

flag=''
n=1
for i in key:
  if(n&1):
    flag+=chr(ord(i)^45)
  else:
    flag+=chr(ord(i)^44)
  n+=1

print flag
#flag{d_with_a_template_phew}
```
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>竟然就特么成功了。降维打击降维打击。</br>