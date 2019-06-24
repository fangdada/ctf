&emsp;&emsp;<font size=2>考试终于考完了我胡汉三又回来了2333，考试之前写了一个加壳器，就不开源了。加壳的思路在之前的一篇博客里面已经介绍过了，[加壳 | 如何用C++编写一个简单的自写壳](https://fanda.cloud/archives/110)，剩下的IAT加密部分或者壳代码部分自由发挥就行了，那么这篇主要是给脱vmp壳做一些铺垫。</font></br>

&emsp;&emsp;<font size=2>众所周知vmp是保护强度最大的壳，攻破vmp也是逆向分析者的一个“毕业资格证”之一，从vmp1.x到vmp3.x这个过程中保护模式一直在变化更新，但不变的是即使vmp保护全关也有一个代码虚拟机，了解虚拟机保护是攻壳的一个基础条件了，本文就从最简单的一个demo开始学习代码虚拟机这个概念（声明一下原文为看雪作者Buu，[原文地址](https://bbs.pediy.com/thread-251409.htm))。</font></br>

&emsp;&emsp;<font size=2>首先跳到main函数处，如下：</font></br>

![main函数](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/main.png)

&emsp;&emsp;<font size=2>第一个printf还是非常正常的，第二个函数就经过了虚拟机处理了，push压入的为虚拟机字节码：</font></br>

![初始化](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/%E5%88%9D%E5%A7%8B%E5%8C%96.png)

![虚拟机字节码]()

&emsp;&emsp;<font size=2>然后首先保存了所有的寄存器，然后做了抬高栈顶的动作，`sub esp,200`很可能是开辟的虚拟机空间，而`sub esp,40`很可能是开辟了虚拟机的寄存器空间，然后esi指向字节码，这里实际上就进入了一个**dispatcher**，根据字节码跳到相应的虚拟机实现，返回时还会判断开辟的虚拟空间是否够用，不够还会再次分配。各个字节码的意义如下：</font></br>

- 0xF6：保存寄存器进入虚拟机环境。

![0xF6](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0xF6.png)

- 0x3D：从字节码load出一个虚拟寄存器索引后压栈，此处为ebp。

![0x3D](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0x3D.png)

- 0x59：将栈上的第一个值压入虚拟环境栈。

![0x59](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0x59.png)

- 0x65：从字节码load出一个虚拟寄存器索引后出栈赋之，此处为0x2C，ebp。

![0x65](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0x65.png)

- 0x9A：栈平衡。

![0x9A](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0x9A.png)

- 0x27：ebp赋给虚拟寄存器esp，相当于更新虚拟栈。

![0x27](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0x27.png)

&emsp;&emsp;<font size=2>所以上面做了一大堆就是用虚拟机完成了`push ebp`这一指令而已，这一指令经常出现在函数的开头，`push ebp; mov ebp,esp`，那么我们来猜猜下一个虚拟指令是不是mov，字节码顺序如下：</font></br>

- 0x3D：load了0x10虚拟寄存器索引，相当于esp，然后压栈。
- 0x3D：load了0x2C虚拟寄存器索引，相当于ebp，然后压栈。
- 0xB5：更新虚拟环境flags寄存器，修改栈中ebp为esp操作。

![0xB5](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0xB5.png)

- 0x65：load了0x2C虚拟寄存器索引相当于ebp后出栈赋之。
- 0x9A：栈平衡。
- 0x27：更新虚拟栈。

&emsp;&emsp;<font size=2>此时`mov ebp,esp`的操作已经完成，只有一个新指令0xB5。接下来就是函数内部的操作了，我们往下分析看看做了什么：</font></br>

- 0x9D：从字节码load一个DWORD后压栈，此处为字符串指针。

![0x9D](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0x9D.png)

- 0xCD：将栈上的一个DWORD压入虚拟栈。

![0xCD](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0xCD.png)

- 0x9A：栈平衡。
- 0x9A：栈平衡。
- 0x27：更新虚拟栈。
- 0x9D：从字节码load一个printf函数地址后压栈。
- 0x9D：从字节码load和一个1压栈。
- 0x9D：从字节码load了一个0xFFFFFFFF后压栈。
- 0x9D：从字节码load了一个0xFFFFFFFF后压栈。
- 0x31：进行了一些莫名的操作，最后压栈printf函数地址：

![0x31](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0x31.png)

- 0xC0：从字节码load一个DWORD后压入虚拟栈，再取出printf真实地址后压入虚拟栈，更新虚拟栈，最后将所有的虚拟寄存器赋给了真实寄存器后跳入printf函数。

![0xC0](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA/screenshot/0xC0.png)

&emsp;&emsp;<font size=2>到这里最简单的虚拟机demo分析完成了，简单来说就是开辟了一个虚拟环境存放栈和寄存器，然后所有的操作都模拟在了虚拟寄存器和栈中，在需要和系统打交道的时候（比如说调用API函数），就还原虚拟寄存器为真实寄存器后调用，保证环境的衔接无缝才是成功的虚拟化。</font></br>