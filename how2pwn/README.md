# How2pwn
## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;初学pwn的话建议移步看看我写的对[malloc原理解析](https://github.com/fangdada/ctf/tree/master/how2pwn/MALLOC)，或者我博客里也有，目前可能文章不多，下面的题目重复的话说明都涉及了，而且题目放上去的不按难度顺序，所以自行看看难度做吧，题目目录下有个**文件夹how2pwn**，这里面都是讲解要做出这道题目的**前置知识**以及相应的**demo**实现，也就是新手基本都推荐先看的（不是全都有，只有最近的复现的题目有，嘻嘻），这样学起来应该比现在清晰一些。那么导航就放在下面了：



## Fast bin

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



## large bin

> largebin attach相比smallbin多拥有fd_nextsize和bk_nextsize，并且largebin可以用malloc_consolidate吞并fastbin块，利用malloc_consolidate经常可以在只能申请fastbin的情况下生成smallbin来leak地址libc_base。

</br>

- [LCTF2017 2ez4u](https://github.com/fangdada/ctf/tree/master/LCTF2017/largebin_2ez4u)
- [HCTF2018 heapstorm](https://github.com/fangdada/ctf/tree/master/HCTF2018/heapstorm)
- [0CTF2018 heapstorm2](https://github.com/fangdada/ctf/tree/master/0CTF2018/heapstorm2)
- ...

</br>



## cache

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
- ...

</br>



## _IO_FILE

> 首先请移步至对[\_IO_FILE](https://github.com/fangdada/ctf/tree/master/how2pwn/_IO_FILE)的详细分析文章，PWN中攻击\_IO\_FILE的题通常都是综合unsortedbin attack修改\_IO\_list\_all，利用其\_chain指向可控地址进而篡改vtable来劫持流程的，明白了这一点，熟悉了vtable调用后就有套路可循了。

</br>

- [HITCON2016 house\_of\_orange](https://github.com/fangdada/ctf/tree/master/how2pwn/house_of_orange/hitcon2016)
- [SCTF2018 sbbs](https://github.com/fangdada/ctf/tree/master/SCTF2018/sbbs)
- [SCTF2018 bufoverflow\_a](https://github.com/fangdada/ctf/tree/master/SCTF2018/bufoverflow_a)
- ...

</br>



# how2kernel

[点这里跳转](https://github.com/fangdada/kernelPWN)
