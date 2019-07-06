&emsp;&emsp;<font size=2>VMProtect1.70比起1.09难度增加了许多，变化也比较大了，在关闭所有保护的情况下也有很多垃圾指令混淆，而且立即数也同样是经过加密的。真实寄存器esp指向的真实栈几乎都是用来混淆的，真正 有用的数据都放进了ebp指向的vmp的虚拟栈里。如果你是想分析受vmp保护的程序片段的话你几乎不用看esp，直接看ebp指向的虚拟栈就行了。同时esi仍然指向字节码，也叫VM_Data。edi指向虚拟环境。接下来不多说，我们通过实际的逆向跟踪来分析VMProtect：</font></br>

&emsp;&emsp;<font size=2>我用的专业版VMProtect V1.70，在专家模式下可以自己设定保护的代码片段（或者说基本块），如果直接从entrypoint从头开始保护的话真是看的一头雾水。受保护程序的源码如下：</font></br>

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

&emsp;&emsp;<font size=2>和之前分析的1.09相同，接下来VMProtect界面如下（对都关，上次被冗杂的垃圾指令恶心到了，所以主要分析虚拟机结构）：</font></br>

![VMP界面](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/VMP%E7%95%8C%E9%9D%A2.png)

![VMP保护界面](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/VMP%E4%BF%9D%E6%8A%A4%E9%80%89%E9%A1%B9.png)

&emsp;&emsp;<font size=2>然后用vmp编译出test.vmp.exe后用x32dbg打开，跟踪到受保护代码的片段处：</font></br>

![push key](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/pushkey.png))

&emsp;&emsp;<font size=2>同样的，这并不是一个随机数，而是一个key，后续会被解密为VM_Data的地址，并赋给esi。然后一直按F7直到跟踪到如下地址：</font></br>

![虚拟机入口](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%85%A5%E5%8F%A3.png)

&emsp;&emsp;<font size=2>上图中`lea ebp, dword ptr ss:[esp+0x3c]`执行完了后ebp就是指向的VM_Stack，就是虚拟栈。随后`add esi, dword ptr ss:[ebp]`执行完了后esi就是指向的VM_Data，就是解密完了字节码地址，然后取出了一个字节码`mov al, byte ptr ds:[esi]`。随后继续F7步入下面的call，其实这里就是一个dispatcher，先解密上面`al`里的字节码：</font></br>

![dispatcher](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%8E%B7%E5%8F%96handler.png)

&emsp;&emsp;<font size=2>可以看到随后根据解密的字节码从一个全局变量取出了一个数赋给了edx，这实际上还要解密，解密完了之后就是一个handler的地址：</font></br>

![解密handler](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%A7%A3%E5%AF%86handler.png)

&emsp;&emsp;<font size=2>如上图，最后这个handler会被放入栈中利用ret跳转并平衡栈（平衡掉垃圾指令产生的垃圾数据）：</font></br>

![跳转handler](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%B7%B3%E8%BD%AChandler.png)

&emsp;&emsp;<font size=2>然后我们进入了handler，根据之前vmp1.09的经验这里应当是pop之前pusha保存的各种寄存器到VM_Context里了，果然：</font></br>

![pop](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/pop%E5%AF%84%E5%AD%98%E5%99%A8.png)

&emsp;&emsp;<font size=2>ebp是指向虚拟栈的，这里从ebp取出了一个DWORD后再`add ebp, 4`实际上就是模拟了pop的动作。继续往下步进：</font></br>

![还原VM_Context](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%BF%98%E5%8E%9FVMContext.png)

&emsp;&emsp;<font size=2>这里将之前“pop”出来的数据赋给了eax索引的一个全局变量里面，其实就是赋给了edi指向的VM_Context。随后又从esi（VM_Data）中取出了一个字节码，判断了虚拟栈是否足够，又回到了dispatcher这里。这样会重复若干次直到之前pushal，pushfd，push key的数据都pop进了VM_Context。然后按理说应该要执行函数准备代码`push ebp`：</font></br>

![push ebp](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/push%E5%AF%84%E5%AD%98%E5%99%A8.png)

&emsp;&emsp;<font size=2>（有点懒用了同一张图）这个eax指向的应当就是VM_Context里的虚拟ebp寄存器了，取出后赋给了edx，然后`sub ebp,4`和`mov  dword ptr ss:[ebp], edx`也是虚拟了push操作，这里`push ebp`的指令执行完了，然后我们再来看看`mov ebp, esp`的部分：</font></br>

![esp2eax](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%99%9A%E6%8B%9Fesp.png)

![push esp](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/pushesp.png)

&emsp;&emsp;<font size=2>首先将ebp（ebp其实就相当于虚拟机中的esp寄存器了），赋给了eax后的`sub ebp,4`和`mov dword ptr ss:[ebp], eax`相当于"push esp"，然后就没了。。。并没有pop到虚拟ebp寄存器的操作，让我有些费解，暂且不管这个。继续往下看就是`mov eax,0`指令：</font></br>

![push0](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/push0.png)

&emsp;&emsp;<font size=2>这里从VM_Data取出了一个字节，这个在后续会被解密为0，也就是一个立即数然后赋给VM_Context里的eax，接着push进了虚拟栈中，并用模拟pop的方式赋给VM_Context里的eax：</font></br>

![解密立即数](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%A7%A3%E5%AF%86%E7%AB%8B%E5%8D%B3%E6%95%B0.png)

![pop0](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/pop0.png)

![moveax](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/moveax.png)

&emsp;&emsp;<font size=2>然后接下来就是`pop ebp`和`ret`的部分了，注意VM_Context里的寄存器位置是毫无逻辑可言的，`pop ebp`赋给的寄存器并不是之前`push ebp`的那个eax索引，而且`ret`也跟vmp1.09的大不相同，如下：</font></br>

![虚拟ret](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%99%9A%E6%8B%9Fret.png)

&emsp;&emsp;<font size=2>VMProtect有自己的一套逻辑，将虚拟寄存器push到栈中，然后以上图的指令方式一个一个放进真实寄存器，还夹杂着垃圾指令。其中`esp+58h`为返回地址，最后一个`ret 54h`平衡栈，至此虚拟机与真实环境算是一个完美对接了。分析这个是真的很折磨人。。。</font></br>

----

### 检测调试器

&emsp;&emsp;<font size=2>我有很多时间都是花在了这里，VMProtect的反调试可以说是做的非常全面了，各种各样的反调试手段都有用到，那么在这里我来讲解一下如何拆解这一个个保护手段。在这里感谢并强烈推荐一篇看雪的文章：[反调试技术总结](https://bbs.pediy.com/thread-225740.htm)，不熟悉反调试的话建议先看看这篇文章。</font></br>

&emsp;&emsp;<font size=2>程序的源码我改为了MessageBox弹窗的了，因为x64dbg调试结束是调用ExitProcess退出的时刻，程序结束的太快看不到是否成功绕过了检测，所以用一个弹窗更醒目一些。在VMProtect编译选项里先钩上检测调试器：</font></br>

![开启检测](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/VMP%E5%BC%80%E5%90%AF%E6%A3%80%E6%B5%8B%E7%95%8C%E9%9D%A2.png)

&emsp;&emsp;<font size=2>然后用调试器打开，直接运行试试看：</font></br>

![检测弹窗](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E6%A3%80%E6%B5%8B%E5%BC%B9%E7%AA%97.png)

&emsp;&emsp;<font size=2>很显然这是被检测到调试器的情况，查看一下调用堆栈：</font></br>

![调用堆栈](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%B0%83%E7%94%A8%E5%A0%86%E6%A0%88.png)

&emsp;&emsp;<font size=2>看来我们无法得到任何信息，VMProtect以某种方式隐藏了流程间的调用，也就是说调用函数并不是用CALL的，那么会是什么？还记得虚拟机里面dispatcher里用的ret吗？没错API的调用也是用ret实现的，叫做VM_RETn。调用的位置如下（vmp2区段里）：</font></br>

![VM_RETn地址](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/VM_RETn%E6%96%AD%E7%82%B9.png)

![VM_RET样子](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/VM_RET%E5%9B%BE%E5%83%8F.png)

&emsp;&emsp;<font size=2>这个其实不难找，用x64dbg的调试菜单里的条件步进就可以完成了，比如把MessageBox这个API的地址记下来，然后用eip == XXXXX（MessageBox的地址）的方式就行了，最后看一下trace log就能发现这个retn。不要在API里下断，VMP有断点检测。</font></br>

&emsp;&emsp;<font size=2>找到了VM_RETn之后我们在这里下断，重新运行程序，就能很清晰的看到VMProtect检测反调试的各种手段了，顺序如下：</font></br>

- IsDebuggerPresent。绕过很简单，在这个API返回前把eax修改为0就行了：

![IsDebuggerPresent](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/IsDebuggerPresent.png)

- CheckRemoteDebuggerPresent。绕过也一样简单，在API返回前把存放调试信息的变量修改为0就行了，在这里就是ebp指向的位置：

![CheckRemoteDebuggerPresent](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/CheckRemoteDebuggerPresent.png)

- CloseHandle。这个算是一种奇技淫巧，利用CloseHandle关闭一个非法句柄时，在正常状态下程序不会产生异常，而是继续往后运行，只是LastError被设置为6，但在调试状态下会触发一个异常然后进入SEH链处理。所以可以用来反调试，处理起来也麻烦一些：

![CloseHandle](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/VM_RETn.png)

&emsp;&emsp;<font size=2>如上图，在edi指向CloseHandle时，VMP壳会利用自实现的GetProcAddress寻找CloseHandle的地址然后调用（在这里不是用之前下断的地址里的ret调用），为了省时省力我们不手动跟踪到调用地址处，而是直接记下CloseHandle这个API的首地址然后用条件步进eip == &CloseHandle的方式来到API内部，如下：</font></br>

![条件步进](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E6%9D%A1%E4%BB%B6%E6%AD%A5%E8%BF%9B.png)

&emsp;&emsp;<font size=2>重申一下不要在API里下断！有断点检测。然后开始步进，过一会儿就会断在CloseHandle里：</font></br>

![CloseHandle入口](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E6%AD%A5%E8%BF%9B%E5%88%B0CloseHandle.png)

&emsp;&emsp;<font size=2>直接在ret 4函数返回处设置为新的运行点（直接修改eip到末尾，跳过函数执行）就行了。</font></br>

![绕过CloseHandle](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E7%BB%95%E8%BF%87CloseHandle.png)

&emsp;&emsp;<font size=2>这样就绕过，瓦解掉了。继续F9看一下反调试函数。</font></br>

- NtQueryInformationProcess。跟CheckRemoteDebuggerPresent一样，F4到函数末尾，然后修改调试信息变量为0就行。

![Query反调试](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/Query%E5%8F%8D%E8%B0%83%E8%AF%95.png)

- NtSetInformationThread。这是一个很致命的程序，运行了这个程序会把调试器跟被调试程序之间剥离，如果你不小心运行了这个函数那么恭喜你，你获得了一个失去控制的程序和调试器。绕过很简单，跟CloseHandle一样在，把首地址的eip设置到末尾退出就行。

![绕过NtSetInformationThread](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%B7%B3%E8%BF%87SetInformationThread.png)

- Int3。这个是一个手动断点，如果是正常的程序就会触发异常，控制流进入SEH异常处理，如果是调试状态就会把异常送给调试器等待处理，绕过的方式就是查看SEH链，手动把控制流修改到SEH handler里，x64dbg里直接在命令行里写上d xxxx（handler地址）跳到handler的反汇编地址里然后设置新的运行点就行了。

![SEH链](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/SEH%E9%93%BE.png)

![d命令](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/d%E5%91%BD%E4%BB%A4%E5%8F%8D%E6%B1%87%E7%BC%96.png)

&emsp;&emsp;<font size=2>（有一张图片丢了，运行完上述命令后，把handler地址设为新的运行点。）</font></br>

- 完事了。

&emsp;&emsp;<font size=2>然后还会遇到一次int3检测和很多很多`IsDebuggerPresent`检测，用上述方法绕过就行了，成功的截图如下：</font></br>

![成功](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/VMP%E8%B0%83%E8%AF%95%E6%88%90%E5%8A%9F.png)

----

### 检测虚拟环境

- 其实我这个版本的VMP只有一种，机器码ED的`in eax,dx`特权指令。原理就是，在正常的R3条件下遇到这条指令的程序会触发异常，而虚拟机状态的程序遇到这个会正常执行。绕过方法也有很多，比如修改返回值，或者直接跳过。比较匪夷所思的是Parallels Desktop遇到这个会抛出异常，而VMware会直接运行然后被检测弹窗23333。我是直接跳过了：

![绕过虚拟机检测](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/VMProtect/VMProtect1.70%E5%88%86%E6%9E%90/screenshot/%E8%B7%B3%E8%BF%87%E8%99%9A%E6%8B%9F%E6%A3%80%E6%B5%8B.png)

----

### 没了
