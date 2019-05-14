&emsp;&emsp;<font size=2>总结一下Linux堆利用技巧，以最经典的glibc2.23为例。所有exploit的目标程序demo是一个漏洞大礼包，都放在上上面了可以下载。目录如下：</font></br>

### 开始之前

> 建议先理解Linux内存管理而不是一上来就"背”堆块的行为，这样底子是不牢的，正好前几天得空简单总结了一下malloc和free的原理（不全面，仅入门用），建议和我一样写个demo，并且调试跟踪一下对理解堆非常有好处：

- [malloc原理跟踪分析（一）]([https://github.com/fangdada/ctf/blob/master/how2pwn/MALLOC/malloc%E5%8E%9F%E7%90%86%E8%AE%B2%E8%A7%A3%EF%BC%88%E4%B8%80%EF%BC%89.md])

- [malloc原理跟踪分析（二）]([https://github.com/fangdada/ctf/blob/master/how2pwn/MALLOC/malloc%E5%8E%9F%E7%90%86%E8%AE%B2%E8%A7%A3%EF%BC%88%E4%BA%8C%EF%BC%89.md])

- [malloc原理跟踪分析（三）]([https://github.com/fangdada/ctf/blob/master/how2pwn/MALLOC/malloc%E5%8E%9F%E7%90%86%E8%AE%B2%E8%A7%A3%EF%BC%88%E4%B8%89%EF%BC%89.md])

- [malloc原理跟踪分析（四）]([https://github.com/fangdada/ctf/blob/master/how2pwn/MALLOC/malloc%E5%8E%9F%E7%90%86%E8%AE%B2%E8%A7%A3%EF%BC%88%E5%9B%9B%EF%BC%89.md])

- [free原理简析]([https://github.com/fangdada/ctf/blob/master/how2pwn/MALLOC/free%E5%8E%9F%E7%90%86%E7%AE%80%E6%9E%90.md])

***

### unsafe unlink

> 非常经典的一个堆溢出利用，我第一次学习这个是在Windows上叫DWORD SHOOT，是因为在老版本中的unlink没有检查，可以达到任意地址写，再后来添加了检查后的版本还想要达到一次SHOOT就比较有限了，但仍然是一个不可低估的漏洞。

- [unsafe unlink漏洞利用剖析]()

***

### waiting...

> ...
