> 建议看本文前先看一下：[一个简单的虚拟机demo](https://github.com/fangdada/ctf/tree/master/how2reverse/%E8%99%9A%E6%8B%9F%E6%9C%BA)
>
> 本文环境：win7+x64dbg+vmp1.09

&emsp;&emsp;<font size=2>刚上手的时候作死下了个vmp3.x，被vmp暴打后老老实实下了个vmp1.x跟着教程做，[原文链接](https://bbs.pediy.com/thread-221681.htm)。从最简单的虚拟机开始吧，本次环境就是vmp1.09，去掉所有保护（相当于默认只有虚拟机），然后添加两个例程（一个main函数，一个自定义函数），被保护程序源码如下：</font></br>

```C
#include <stdio.h>

void ZeroEax()
{
    __asm mov eax,0
}
int main()
{
    ZeroEax();
    printf("hello,world1!\n");

    return 0;
}
```

&emsp;&emsp;<font size=2>VMProtect界面如下图：</font></br>

![VMP界面](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/VMP%E4%BF%9D%E6%8A%A4.png)

&emsp;&emsp;<font size=2>使用VMProtect生成后两个函数都已经被加上了保护，在这里我使用x32dbg跟踪到main函数，如下：</font></br>

![入口](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/%E5%85%A5%E5%8F%A3pushkey.png)

&emsp;&emsp;<font size=2>jmp之后就是虚拟机的入口代码，如下（注意这一段代码会被反复调用，后续会提及）：</font></br>

![虚拟机入口](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%85%A5%E5%8F%A3.png)

&emsp;&emsp;<font size=2>注意上面的push并不是压入了一个随机数，而是一个有意义的key，包括后来你看到的push xxxx都是表面上无意义但实际上都有被用来计算地址，这也是vmp的一种加密吧。我们继续往下看，这是一个非常经典的虚拟机循环，取出字节码跳到对应的handler：</font></br>

![虚拟机循环](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%BE%AA%E7%8E%AF.png)

&emsp;&emsp;<font size=2>在进入虚拟机的时候，第一件事就是用虚拟机循环将之前pushal和pushfd保存的寄存器pop到虚拟机环境里（叫做vm_context，注意vm_context内寄存器位置每次随机)，再加一个计算地址用的key，如下：</font></br>

![还原vmcontext](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/%E8%BF%98%E5%8E%9Fvmcontext.png)

&emsp;&emsp;<font size=2>循环了10次（8个寄存器，1个eflags寄存器和1个key），完了之后就是用虚拟机的方式去执行源程序里的一条条汇编指令了，比如push ebp，在虚拟机里就是：</font></br>

![vmcontext入栈](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/vmcontext%E5%85%A5%E6%A0%88.png)

&emsp;&emsp;<font size=2>其中eax指向的就是vm_context中ebp的索引，这样就完成了一个`push ebp`指令。然后就是`mov ebp,esp`，这两比较简单不多说了，然后根据源代码就是调用ZeroEax()函数了，在vmp中调用函数（无论是api还是自定义函数）会把vm_context里的寄存器一个个都push了然后pop到真实寄存器中然后使用ret跳入函数。至于为什么用ret跳不用call？不会出问题吗？事实上vmp已经用某种方式将函数地址，返回地址和参数地址都push进了栈，无缝实现了函数的正常调用，有点汇编基础的都能看懂的。</font></br>

&emsp;&emsp;<font size=2>ret跳入了自定义函数后仍然是一个虚拟机入口，就像是当初刚进入main函数一样，同样接下来的虚拟机的第一件事就是循环将pushfd pushal的寄存器一个一个pop到vm_context，不多讲解。自定义函数非常简单，只有一个`mov eax,0`操作。函数开头的`push ebp; mov ebp,esp`就不重复说了，对于`mov eax,0`虚拟机里如下实现：</font></br>

![mov0](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/mov0.png)

![ret](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/ret.png)

&emsp;&emsp;<font size=2>0作为一个立即数被保存在字节码中，在虚拟机循环中load出0，push入栈，然后直接pop给vm_context里的eax就完成了mov的操作。接下来就是ret了，pop还原所有vm_context，然后用ret跳出（返回地址就是之前调用的时候push的）。</font></br>

&emsp;&emsp;<font size=2>重新返回到main函数之后还是要进行一个进入虚拟机操作，也就是执行虚拟机入口代码，再循环恢复vm_context环境。然后继续往下执行，接下来调用了printf函数（这个跟调用自定义函数差不多，push参数，返回地址和printf函数地址之后从vm_context还原真实寄存器，ret跳入printf）。执行完了printf后再回到虚拟机入口代码，恢复vm_context，后继续执行剩下的代码，原理基本如此。但接下来的`add esp,4`，`xor eax,eax`两条 有些不太一样，前者是先平衡了printf函数地址和返回地址，然后再平衡了参数，也就是说esp+8之后再esp+4平衡的，而后者不是直接用的xor指令而是用了`~(n)&n=0`来间接实现xor清零的，如下：</font></br>

![xor](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/xor%E6%B7%B7%E6%B7%86.png)

### 现在把保护都打开

&emsp;&emsp;<font size=2>保护全关的前期版本的vmp还是比较容易分析的，接下来我们把vmp保护都开了，如下图：</font></br>

![VMP保护全开](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/VMP%E4%BF%9D%E6%8A%A4%E5%85%A8%E5%BC%80.png)

&emsp;&emsp;<font size=2>可能看上去很厉害，但是我们的demo程序是单线程的，而且还是console程序，因此可能很多其实都没有用到，level也开了max protection 。可能最终生效比较多的是Encoding of a p-code，反正我开了之后我整整按了快半小时F7才从main调用了自定义函数2333。我是一个没有感情的F7机器。所有的立即数以及函数返回地址还有字节码全都被加密了，全都需要经过计算才能得到：</font></br>

![全保护虚拟机入口](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.09%E5%88%86%E6%9E%90/screenshot/%E5%85%A8%E4%BF%9D%E6%8A%A4%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%85%A5%E5%8F%A3.png)

&emsp;&emsp;<font size=2>如上图是虚拟机入口处的代码，我们可以看到字节码取出来后也要经过运算才能得到最终的，每次循环都要计算过。立即数哪怕是0也是经过了复杂的运算和庞大的垃圾指令才得到赋给vm_context的eax的。其中构造函数跳转那一部分是真的恶心，我按了20分钟F7才终于看到ret。大家自己试试吧，总结来说，开了全保护之后跟原来的差不多，就是垃圾指令太多了，如果要脱全保护的vmp1.09的话要好好想想如何对付这些垃圾指令，如果只是学习vmp的机制的话也还是可以接受的。</font></br>
