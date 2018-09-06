# SUCTF2018 simpleformat
## Author:文火

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>老样子，还是贴出我学习的[原wp](https://github.com/Mem2019/Mem2019.github.io/tree/master/writeups/suctf2018)，膜一下。程序比较简单，但是能这样用ida python正则表达式来数的大佬还是需要学习一下的，要避免做机械无意义的劳动。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>程序利用了print的format格式里的*和$n配合指定变量大小并用%n赋值来暗含了flag，所以知道了怎么搞到flag就简单了。提取出需要的方程式的参数然后用z3这样的约束器解就可以了。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>ida的python脚本我也搬运过来了。</font></br>

脚本
=====

IDApython：
```python
import re
def str_to_equation(string):
	res = []
	for x in xrange(2, 20):
		f = "%1\\$\\*" + str(x) + "\\$s"
		res.append(len([m.start() for m in re.finditer(f, string)]))
	return res

def get_all_formats():
	res = []
	for addr in XrefsTo(0x400590, flags=0):
		mov_esi = addr.frm - 12
		assert GetMnem(mov_esi) == "mov" and "esi" in GetOpnd(mov_esi, 0)
		res.append(GetString(GetOperandValue(mov_esi, 1)))
	return res

def get_equations():
	equations = []
	formats = get_all_formats()
	for s in formats:
		equations.append(str_to_equation(s))
	return equations

def get_results():
	res = []
	p = 0x627100
	for i in xrange(0, 18):
		res.append(Dword(p + 4 * i))
	return res
```

z3脚本：
```python
from z3 import *
import binascii

s=Solver()

args=[[19, 8, 0, 5, 0, 6, 27, 19, 6, 22, 16, 0, 1, 23, 2, 29, 14, 22], [26, 18, 9, 14, 3, 1, 0, 6, 20, 9, 24, 5, 6, 14, 13, 20, 7, 1], [16, 29, 5, 16, 11, 15, 15, 7, 26, 29, 17, 11, 12, 4, 6, 9, 21, 13], [25, 8, 3, 30, 16, 30, 30, 23, 3, 20, 11, 8, 27, 5, 5, 2, 20, 25], [17, 1, 15, 5, 29, 9, 24, 17, 29, 8, 27, 13, 19, 27, 28, 28, 5, 17], [16, 7, 12, 10, 10, 21, 11, 24, 10, 16, 1, 1, 25, 19, 28, 13, 23, 29], [26, 27, 27, 29, 24, 17, 24, 19, 30, 2, 10, 14, 11, 24, 17, 0, 21, 1], [30, 20, 24, 6, 6, 14, 9, 7, 22, 9, 7, 18, 22, 23, 22, 21, 7, 25], [8, 9, 9, 30, 15, 26, 17, 28, 12, 11, 26, 28, 22, 20, 5, 2, 1, 11], [4, 9, 25, 17, 10, 29, 28, 25, 12, 30, 2, 18, 8, 17, 8, 9, 8, 28], [5, 10, 23, 5, 30, 0, 14, 0, 28, 29, 23, 0, 22, 2, 27, 27, 18, 16], [0, 20, 3, 11, 28, 21, 2, 17, 17, 9, 22, 5, 19, 25, 29, 10, 27, 22], [12, 16, 4, 4, 4, 4, 15, 1, 26, 24, 14, 24, 18, 23, 4, 13, 17, 13], [26, 17, 11, 8, 29, 20, 7, 20, 26, 14, 28, 27, 28, 16, 26, 16, 9, 10], [22, 13, 23, 13, 20, 15, 5, 3, 1, 14, 29, 1, 0, 19, 13, 27, 23, 24], [15, 26, 23, 5, 5, 15, 20, 20, 7, 9, 5, 15, 20, 27, 8, 7, 18, 17], [12, 4, 15, 8, 1, 6, 27, 22, 2, 25, 15, 14, 25, 15, 18, 21, 28, 12], [4, 24, 11, 1, 22, 26, 11, 16, 18, 15, 18, 17, 1, 30, 9, 7, 19, 30]]

result=[5462280, 4346506, 5891159, 6839864, 7912833, 7049790, 7455784, 7311612, 6299256, 7114100, 7037043, 6873051, 5644794, 8014197, 6432215, 6638450, 6959905, 6705884]

b=[]
for i in range(0,18):
  b.append(BitVec(i,16))

for i in range(0,18):
  s.add(Sum([b[j]*args[i][j] for j in range(0,18)])==result[i])

flag=''
if s.check()==sat:
  m=s.model()
  for i in m:
    flag+=binascii.a2b_hex(hex(m[i].as_long())[2:])[::-1]
  
print flag

```
