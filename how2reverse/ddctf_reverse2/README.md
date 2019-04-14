# DDCTF2019 reverse2

&emsp;&emsp;<font size=2>这题涉及到了脱壳（虽然只是压缩壳），看了一下我竟然没有现成的脱壳的文章，所以就在这里另写一篇。脱壳的步骤如下：</font></br>

- 使用ESP定律（或其他）跟踪到OEP；
- 使用LordPE dump内存映像；
- 使用ImportREC修复IAT表；
- 工具可以去看雪里下。

&emsp;&emsp;<font size=2>其实像压缩壳这样的直接用脱壳机也行，但是脱壳机出了问题的话往往不知道原因是什么，出于做题我还是喜欢手动脱壳，我个人建议脱壳过程中要再加一步：`关闭ASLR！`</font></br>

&emsp;&emsp;<font size=2>因为修复IAT表的时候容易因为重定向的问题会访问到一个不正确的地址导致库函数无法正确调用而脱壳失败，所以关闭ASLR也应当是脱壳的一部分，我的环境是Windows7，可以用微软官方的工具EMET（叫啥体验增加工具）关闭，我只有Windows7的，想要可以找我拿，Windows10应该可以直接去官网里下。好了，因为懒不想放图片，打开EMET你们自己也应当会用，就不讲这个了，然后正式进入脱壳步骤：</font></br>

### ESP定律

&emsp;&emsp;<font size=2>首先使用ollydbg打开题目，然后F7完成pushad指令后，在ollydbg命令行里输入`hr 0xXXXX`，这个地址就是你esp寄存器的值，然后直接按F9就可以到达OEP附近（但是还没到），继续执行若干条指令可以看到跳转到以`call 0x400XXX jmp 0x400XXX`的一个地方，这就是OEP。</font></br>

### LordPE dump

&emsp;&emsp;<font size=2>随后用**管理员身份**打开LordPE，找到题目进程后右键，点击full dump，完整转存内存映像。</font></br>

### ImportREC修复IAT

&emsp;&emsp;<font size=2>然后同样最好用管理员打开ImportREC，在左下角OEP那儿输入自己在ollydbg找到的OEP（减去基址），然后点击IATAutosearch，提示找到了之后就点击右下角选择映像文件后就修复完成了，然后重新运行下dumped_.exe试试成功了没。</font></br>

### 解题

&emsp;&emsp;<font size=2>不太想写，只能输入0~9，A~F，就一个加密函数存在位运算，不知道z3出了啥问题是unsat，也有可能我写的有问题，最后是手动算的，那我直接把解题过程发一下就算完事了：</font></br>

```python
table=[0x37,0x34,0x35,0x32,0x33,0x30,0x31,0x3E,0x3F,0x3C,0x3D,0x3A,0x3B,0x38,0x39,0x26,0x27,0x24,0x25,0x22,0x23,0x20,0x21,0x2E,0x2F,0x2C,0x17,0x14,0x15,0x12,0x13,0x10,0x11,0x1E,0x1F,0x1C,0x1D,0x1A,0x1B,0x18,0x19,0x6, 0x7,0x4,0x5,0x2,0x3,0x0,0x1,0x0E,0x0F,0x0C,0x46,0x47,0x44,0x45,0x42,0x43,0x40,0x41,0x4E,0x4F,0x5D,0x59]

shoudbe="reverse+"
output=[]

for i in shoudbe:
    output.append(table.index(ord(i)^0x76))
# [43, 30, 47, 30, 43, 44, 30, 62]
# [0x2b,0x1e,0x2f,0x1e,0x2b,0x2c,0x1e,0x3e]
'''
v17 = Dst >> 2;
v18 = (v15 >> 4) + 16 * (Dst & 3);
v19 = (v16 >> 6) + 4 * (v15 & 0xF);
i = v16 & 0x3F;
'''

print(output)

'''
flag1=0xad
flag2=0xeb
flag3=0xde

flag4=0xae
flag5=0xc7
flag6=0xbe
ADEBDEAEC7BE
'''
```

&emsp;&emsp;<font size=2>（还以为要flag，白瞎了两小时23333。）</font></br>

