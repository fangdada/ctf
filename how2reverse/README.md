# How2reverse
## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>终于终于，我终于更新how2reverse了23333，鸽了好久，前一阵子太忙，然后又学习Linux kernel和angr框架，后来出了莫名其妙的问题后卡住了，没事做就来更新下这个。好了废话说完了，来看看how2reverse主要讲什么：</font></br>

## 动态调试

> 我始终认为动态调试是一个逆向分析师必须要熟练掌握的技巧，无论是CTF题还是真实对抗环境，都要能利用动态调试见招拆招找到自己想要的。建议工具：IDA远程调试，GDB+插件（例如peda，pwndbg皆可）。

</br>

- [0CTF2016 momo](https://github.com/fangdada/ctf/tree/master/0CTF2016/momo)
- [QCTF2018 babyre](https://github.com/fangdada/ctf/tree/master/QCTF2018/babyre)
- [鹏城杯2018初赛 badblock](https://github.com/fangdada/ctf/tree/master/%E9%B9%8F%E5%9F%8E%E6%9D%AF2018/badblock)
- [RCTF2018 simple_re](https://github.com/fangdada/ctf/tree/master/RCTF2018/simple_re)
- [RCTF2018 magic](https://github.com/fangdada/ctf/tree/master/RCTF2018/magic)
- [RCTF2018 babyvm](https://github.com/fangdada/ctf/tree/master/RCTF2018/babyvm)
- ...

</br>

## Z3-Solver

> 利用符号变量约束器求解唯一解在CTF中也是一种解法，到如今这成为了CTFer必须掌握的一个技巧。与爆破类似，必须知道程序的逻辑，例如加密算法，之后利用python的z3模块编写脚本约束求解。

</br>

- [SUCTF2018 simpleformat](https://github.com/fangdada/ctf/tree/master/how2reverse/simpleformat)
- [RCTF2018 babyre2](https://github.com/fangdada/ctf/tree/master/RCTF2018/babyre2)
- [0CTF2017 engineTest](https://github.com/fangdada/ctf/tree/master/0CTF2017/engineTest)
- ...

</br>


## 静态分析

> 只需要静态分析的题常常花样特别多，除去偶尔的逆向pyc和mips或是直接一个log文件，爆破题和加密题常是静态分析题，我个人喜欢配合GDB验证自己还原的算法是否出错。

</br>

- [QCTF2018 asong](https://github.com/fangdada/ctf/tree/master/QCTF2018/asong)
- [RCTF2018 babyre](https://github.com/fangdada/ctf/tree/master/RCTF2018/babyre)
- [QCTF2018 babymips](https://github.com/fangdada/ctf/tree/master/QCTF2018/babymips)
- [0CTF2017 py](https://github.com/fangdada/ctf/tree/master/0CTF2017/py)
- [0CTF2016 trace](https://github.com/fangdada/ctf/tree/master/0CTF2016/trace)
- [SCTF2018 babymips](https://github.com/fangdada/ctf/tree/master/SCTF2018/babymips)
- [SUCTF2018 Enigma](https://github.com/fangdada/ctf/tree/master/SUCTF/Engima)
- [starCTF2018 milktea](https://github.com/fangdada/ctf/tree/master/starctf/milktea)
- [CISCN2018 reverse_03](https://github.com/fangdada/ctf/tree/master/how2reverse/reverse_03)
- [SUCTF2018 simpleformat](https://github.com/fangdada/ctf/tree/master/how2reverse/simpleformat)
- ...

</br>

## 爆破

> 爆破常用与一些加密题，例如爆破hash算法。这一类题通常需要还原算法，若爆破时间过长应注意一下是否是自己的脚本问题或是解题思路。

</br>

- [RCTF2018 babyre](https://github.com/fangdada/ctf/tree/master/RCTF2018/babyre)
- [RCTF2018 babyvm](https://github.com/fangdada/ctf/tree/master/RCTF2018/babyvm)
- [RCTF2018 simple_re](https://github.com/fangdada/ctf/tree/master/RCTF2018/simple_re)
- [RCTF2018 magic](https://github.com/fangdada/ctf/tree/master/RCTF2018/magic)
- [SUCTF2018 Enigma](https://github.com/fangdada/ctf/tree/master/SUCTF/Engima)
- [CISCN2018 reverse_03](https://github.com/fangdada/ctf/tree/master/how2reverse/reverse_03)
- ...

</br>

## 脱壳

>壳分为压缩壳与加密壳，在Windows下加密壳比Linux下的加密壳多，但CTF中大多都是压缩壳，无论是使用脱壳机还是手动脱壳都十分简单，在这里我都用手动的方式脱壳。

</br>

- [DDCTF2019 reverse2](https://github.com/fangdada/ctf/tree/master/how2reverse/ddctf_reverse2)

</br>

## 待续

> …...

</br>

- ...

</br>
