>  环境：windows XP 32位，ollydbgv1.1，LordPE，ImportREC

&emsp;&emsp;<font size=2>这篇文章我是首先根据看雪的一篇原文学习后总结的（[这是原文](https://bbs.pediy.com/thread-225733.htm)），同时也非常感谢原文作者给予我的帮助，帮我解决了IAT修复时的异常问题。</font></br>

&emsp;&emsp;<font size=2>目前逆向反逆向的对抗无非分为：反调试，代码混淆，壳，算法等等。那么这篇文章不是来扫盲的，而是通过一个未知壳的脱壳来给你提供一种思路，话不多说，下面直接开干，首先查壳：</font></br>

![peid](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/peid.png)

&emsp;&emsp;<font size=2>可以看到和一般的程序不同，什么都没查出来，那么这是一个未知壳，其行为就需要我们自己去探索了。用od打开程序，非常显眼的第一个就是pushad，pushfd：</font></br>

![入口](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E5%85%A5%E5%8F%A3.png)

&emsp;&emsp;<font size=2>用ESP定律试一下，然后再F7单步执行若干次就到了OEP：</font></br>

![OEP](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E5%85%A5%E5%8F%A3.png)

&emsp;&emsp;<font size=2>但看那条`call dword ptr [475080]`应当是`GetVersion`这个API函数，但od没有显示出来，IAT表可能有问题，查看一下内存数据，果然被填充了别的地址：</font></br>

![假IAT内存数据](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E5%81%87IAT%E5%86%85%E5%AD%98%E6%95%B0%E6%8D%AE.png)

&emsp;&emsp;<font size=2>这样子的话是不能直接脱壳的，因为原来的IAT的内容可能在"壳”里，直接脱去的话会把IAT也丢掉了，解决办法一般都是有两种：</font></br>

- 根据IAT加密方式反加密手动修复；

- 在壳中寻找原来的IAT内容然后修复IAT；

&emsp;&emsp;<font size=2>这个壳的IAT加密方式比较偏向后者，所以我们寻找一下IAT替代的规律，单步步入475080这个本来应当是GetVersion函数地址的地方，分析一下可以看到跳转到了真正的GetVersion，其地址被藏在了edi指向的地址：</font></br>

![假IAT](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E5%81%87IAT.png)

&emsp;&emsp;<font size=2>那么我们在这里下断，看看这里是什么时候被放上GetVersion的地址的（这里注意一点：壳的映射地址也是随机的，所以根据情况有所不同，你的地址很可能跟我不一样）：</font></br>

![硬件断点](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E7%A1%AC%E4%BB%B6%E6%96%AD%E7%82%B9.png)

&emsp;&emsp;<font size=2>然后按restart重新开始一下，让控制流回到壳的开始。这里再注意：可能重新开始后映射地址又变化了，所以原来设置的硬件断点可能无效了，可以先在475000处下断到第一次填充IAT的地方然后记一下映射基址，然后断点下在映射基址+505D，在这里我展示一下这种操作方式，首先下断475000，然后F9若干次可以看到这里填充的地方：</font></br>

![获取基址](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E8%8E%B7%E5%8F%96%E5%9F%BA%E5%9D%80.png)

&emsp;&emsp;<font size=2>eax是3E2264，因此我们可以得到映射基址是3E0000，加上我们之前获取的函数的位置后2字节505D，我们下断在3E505D，然后F9继续运行：</font></br>

![获取API](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E8%8E%B7%E5%8F%96API.png)

&emsp;&emsp;<font size=2>成功断在这里了，我们记下这里的地址，然后可以用ollydbg脚本在这里下断后获取edx的值（也就是IAT原内容），然后等到了填充IAT的地址时我们用真正的函数值去覆盖刚填充完的假地址，就能成功修复了，ollydbg脚本如下（我跟原作者用的地址可能不一样，思路也稍有差别）：</font></br>

```
// 定义变量,初始化变量
VAR dwGetAPIAddr
VAR dwWriteIATAddr
VAR dwOEP VAR dwTmp
 
MOV dwGetAPIAddr, 003814DC    // 获取 API 地址的地方     
MOV dwWriteIATAddr, 00380897  // 填充 IAT 的地方
MOV dwOEP, 0047148B            // OEP
 
// 清理环境
BC    // 清理软件断点
BPHWC  // 清理硬件断点
BPMC  // 清理内存断点
 
// 设置断点
BPHWS dwOEP, "x"
BPHWS dwGetAPIAddr, "x"
BPHWS dwWriteIATAddr, "x"
 
// 构造循环
LOOP1: 
 
// 运行程序
RUN
 
// 判断 是 获取 API 地址的地方
cmp eip,dwGetAPIAddr
JNZ SIGN1
 
MOV dwTmp, edx
jmp LOOP1 
 
// 判断 是 填充 IAT 的地方
SIGN1:
 
cmp eip,dwWriteIATAddr
JNZ SIGN2 
 
MOV [edx],dwTmp
 
jmp LOOP1 
// 判断是 OEP ，结束了
SIGN2:
cmp eip,dwOEP
JZ EXIT1
 
jmp LOOP1  // 脚本结束
 
EXIT1:
 
MSG "yes，今晚吃鸡！"
```

&emsp;&emsp;<font size=2>ollydbg运行这个脚本可以看到IAT都被修复了，然后就是常规LordPE dump内存映像和importREC修复了。这里不多讲，最终效果如下：</font></br>

![真实IAT](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E7%9C%9F%E5%AE%9EIAT.png)

![最终效果](https://raw.githubusercontent.com/fangdada/ctf/master/how2reverse/%E8%84%B1%E5%A3%B3/%E6%9C%AA%E7%9F%A5%E5%A3%B31/screenshot/%E6%9C%80%E7%BB%88%E6%95%88%E6%9E%9C.png)