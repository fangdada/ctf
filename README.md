# How2pwn
## Author: Wenhuo

### - 注：个人博客已开通，导航更直观：https://fanda.cloud 
&nbsp;&nbsp;&nbsp;&nbsp;我个人做过的CTF的bin题收集，有逆向和pwn两个方向。最近主要研究pwn，所以把**how2pwn**改版一下方便自己查阅也方便别人学了（how2reverse可能以后再整理吧嘻嘻），各个知识点都改成**导航去相应题目**的，重复的话说明都涉及了，而且题目放上去的不按难度顺序，所以自行看看难度做吧，题目目录下有个**文件夹how2pwn**，这里面都是讲解要做出这道题目的**前置知识**以及相应的**demo**实现，也就是推荐新手先看的（不是全都有，只有最近复现的题目有，嘻嘻），这样学起来应该比现在清晰一些。那么导航就放在下面了：

## fastbin

> 同一组大小的fastbin被free后由fd指针指向前一个freed的chunk，伪造fastbin要注意绕过size check，e.g. 0x70大小的堆块，伪造的size要在0x70-0x7f的区间里。

</br>

- [LCTF2016 pwn200](https://github.com/fangdada/ctf/tree/master/how2pwn/house_of_spirit/lctf2016_pwn200)
- [QCTF2018 NoLeak](https://github.com/fangdada/ctf/tree/master/QCTF2018/NoLeak)
- [RCTF2018 RNote3](https://github.com/fangdada/ctf/tree/master/RCTF2018/RNote3)
- [RCTF2018 babyheap](https://github.com/fangdada/ctf/tree/master/RCTF2018/babyheap)
- [RCTF2018 stringer](https://github.com/fangdada/ctf/tree/master/RCTF2018/stringer)
- [tiesan2018 littlenote](https://github.com/fangdada/ctf/tree/master/tiesan2018/littlenote)
- [tiesan2018 bookstore](https://github.com/fangdada/ctf/tree/master/tiesan2018/bookstore)
- ...

</br>

## largebin

> largebin attach相比smallbin多拥有fd_nextsize和bk_nextsize，并且largebin可以用malloc_consolidate吞并fastbin块，利用malloc_consolidate经常可以在只能申请fastbin的情况下生成smallbin来leak地址libc_base。

</br>

- [LCTF2017 2ez4u](https://github.com/fangdada/ctf/tree/master/LCTF2017/largebin_2ez4u)
- [HCTF2018 heapstorm](https://github.com/fangdada/ctf/tree/master/HCTF2018/heapstorm)
- [0CTF2018 heapstorm2](https://github.com/fangdada/ctf/tree/master/0CTF2018/heapstorm2)
- ...

</br>


## tcache

> 最近tcache机制的pwn题越来越多，因此必须得明白tcache机制与往常glibc2.23等版本的不同处，tcache的安全检查特别少，因此这类题的难点通常就在如何leak出libc基址以及如何创建重叠堆块。

</br>

- [QCTF2018 babyheap](https://github.com/fangdada/ctf/tree/master/QCTF2018/babyheap)
- [HITCON2018 children_tcache](https://github.com/fangdada/ctf/tree/master/HITCON2018/child_tcache)
- [LCTF2018 easy_heap](https://github.com/fangdada/ctf/tree/master/LCTF2018/easyheap)
- ...

</br>

## unsafe unlink

> 对刚学堆利用的bin手来说这通常是第一课，目前只放这一题，后续还有largebin下的unlink实现

</br>

- [demo](https://github.com/fangdada/ctf/tree/master/how2pwn/unsafe_unlink)
- [0CTF2018 heapstorm2](https://github.com/fangdada/ctf/tree/master/0CTF2018/heapstorm2)
- [SCTF2018 bufoverflow\_a](https://github.com/fangdada/ctf/tree/master/SCTF2018/bufoverflow_a)
- ...

</br>


## _IO_FILE

> PWN中攻击\_IO\_FILE的题通常都是综合unsortedbin attack修改\_IO\_list\_all，利用其\_chain指向可控地址进而篡改vtable来劫持流程的，明白了这一点，熟悉了vtable调用后就有套路可循了。

</br>

- [HITCON2016 house\_of\_orange](https://github.com/fangdada/ctf/tree/master/how2pwn/house_of_orange/hitcon2016)
- [SCTF2018 sbbs](https://github.com/fangdada/ctf/tree/master/SCTF2018/sbbs)
- [SCTF2018 bufoverflow\_a](https://github.com/fangdada/ctf/tree/master/SCTF2018/bufoverflow_a)
- ...

</br>

# how2kernel
[点这里跳转](https://github.com/fangdada/kernelPWN)

***

# How2reverse

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>终于终于，我终于更新how2reverse了23333，鸽了好久，前一阵子太忙，然后又学习Linux kernel和angr框架，后来出了莫名其妙的问题后卡住了，没事做就来更新下这个。好了废话说完了，来看看how2reverse主要讲什么：</font></br>

## 动态调试

> 我始终认为动态调试是一个逆向分析师必须要熟练掌握的技巧，无论是CTF题还是真实对抗环境，都要能利用动态调试见招拆招找到自己想要的。建议工具：IDA远程调试，GDB+插件（例如peda，pwndbg皆可）。

</br>

- [0CTF2016 momo](https://fanda.cloud/2019/03/16/0ctf2016-momo/)
- [QCTF2018 babyre](https://fanda.cloud/2019/03/17/qctf2018-babyre/)
- [鹏城杯2018初赛 badblock](https://fanda.cloud/2019/03/17/%E9%B9%8F%E5%9F%8E%E6%9D%AF2018%E5%88%9D%E8%B5%9B-badblock/)
- [RCTF2018 simple_re](https://fanda.cloud/2019/03/17/rctf2018-simple_re/)
- [RCTF2018 magic](https://fanda.cloud/2019/03/17/rctf2018-magic/)
- [RCTF2018 babyvm](https://fanda.cloud/2019/03/17/rctf2018-babyvm/)
- ...

</br>

## Z3-Solver

> 利用符号变量约束器求解唯一解在CTF中也是一种解法，到如今这成为了CTFer必须掌握的一个技巧。与爆破类似，必须知道程序的逻辑，例如加密算法，之后利用python的z3模块编写脚本约束求解。

</br>

- [SUCTF2018 simpleformat](https://fanda.cloud/2019/03/17/suctf2018-simpleformat/)
- [RCTF2018 babyre2](https://fanda.cloud/2019/03/17/rctf2018-babyre2/)
- [0CTF2017 engineTest](https://fanda.cloud/2019/03/16/0ctf2017-enginetest/)
- ...

</br>


## 静态分析

> 只需要静态分析的题常常花样特别多，除去偶尔的逆向pyc和mips或是直接一个log文件，爆破题和加密题常是静态分析题，我个人喜欢配合GDB验证自己还原的算法是否出错。

</br>

- [QCTF2018 asong](https://fanda.cloud/2019/03/17/qctf2018-asong/)
- [RCTF2018 babyre](https://fanda.cloud/2019/03/17/rctf2018-babyre/)
- [QCTF2018 babymips](https://fanda.cloud/2019/03/17/qctf2018-babymips/)
- [0CTF2017 py](https://fanda.cloud/2019/03/17/0ctf2017-py/)
- [0CTF2016 trace](https://fanda.cloud/2019/03/16/0ctf2016-trace/)
- [SCTF2018 babymips](https://fanda.cloud/2019/03/17/sctf2018-babymips/)
- [SUCTF2018 Enigma](https://fanda.cloud/2019/03/17/suctf2018-enigma/)
- [starCTF2018 milktea](https://fanda.cloud/2019/03/17/starctf2018-milktea/)
- [CISCN2018 reverse_03](https://fanda.cloud/2019/03/17/ciscn2018-reverse_03/)
- [SUCTF2018 simpleformat](https://fanda.cloud/2019/03/17/suctf2018-simpleformat/)
- ...

</br>

## 爆破

> 爆破常用与一些加密题，例如爆破hash算法。这一类题通常需要还原算法，若爆破时间过长应注意一下是否是自己的脚本问题或是解题思路。

</br>

- [RCTF2018 babyre](https://fanda.cloud/2019/03/17/rctf2018-babyre/)
- [RCTF2018 babyvm](https://fanda.cloud/2019/03/17/rctf2018-babyvm/)
- [RCTF2018 simple_re](https://fanda.cloud/2019/03/17/rctf2018-simple_re/)
- [RCTF2018 magic](https://fanda.cloud/2019/03/17/rctf2018-magic/)
- [SUCTF2018 Enigma](https://fanda.cloud/2019/03/17/suctf2018-enigma/)
- [CISCN2018 reverse_03](https://fanda.cloud/2019/03/17/ciscn2018-reverse_03/)
- ...

</br>


## 待续

> …...

</br>

- ...

</br>
