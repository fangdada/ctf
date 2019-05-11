&emsp;&emsp;<font size=2>在[上一个章节](<https://fanda.cloud/archives/60>)，我们已经大致认识到了malloc的堆块在内存中的结构，接下来我们就开始从源码角度分析内存分配的原理：</font></br>

```C
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
```

&emsp;&emsp;<font size=2>其实上一节我没有提及的是，第一次使用malloc函数时，\__malloc_hook里其实是有一个函数的，叫malloc_hook_ini，其定义如下：</font></br>

```C
static void *
malloc_hook_ini (size_t sz, const void *caller)
{
  __malloc_hook = NULL;
  ptmalloc_init ();
  return __libc_malloc (sz);
}
```

&emsp;&emsp;<font size=2>该函数首先把\__malloc_hook置0防止再次调用（因为返回地址是\_\_libc_malloc，然后调用了ptmalloc_init()这个做初始化工作的主体函数：</font></br>

```C
static void
ptmalloc_init (void)
{
  if (__malloc_initialized >= 0)
    return;

  __malloc_initialized = 0;

#ifdef SHARED
  /* In case this libc copy is in a non-default namespace, never use brk.
     Likewise if dlopened from statically linked program.  */
  Dl_info di;
  struct link_map *l;

  if (_dl_open_hook != NULL
      || (_dl_addr (ptmalloc_init, &di, &l, NULL) != 0
          && l->l_ns != LM_ID_BASE))
    __morecore = __failing_morecore;
#endif
```

&emsp;&emsp;<font size=2>对于_dl_addr这个函数不需要太过深入了解，只要看注释就行了，其作用就是检测主程序是否是动态链接还是静态链接并以此来决定是否使用brk内配器。我们继续往下看：</font></br>

```C
  thread_arena = &main_arena;
  thread_atfork (ptmalloc_lock_all, ptmalloc_unlock_all, ptmalloc_unlock_all2);
  const char *s = NULL;
  if (__glibc_likely (_environ != NULL))
    {
      char **runp = _environ;
      char *envline;

      while (__builtin_expect ((envline = next_env_entry (&runp)) != NULL,
                               0))
        {
          size_t len = strcspn (envline, "=");

          if (envline[len] != '=')
            /* This is a "MALLOC_" variable at the end of the string
               without a '=' character.  Ignore it since otherwise we
               will access invalid memory below.  */
            continue;

          switch (len)
            {
              //....
            }
      }
      if (s && s[0])
      {
        //...
      }
      void (*hook) (void) = atomic_forced_read (__malloc_initialize_hook);
      if (hook != NULL)
         (*hook)();
      __malloc_initialized = 1;
}
```

&emsp;&emsp;<font size=2>后来把thread_arena设置为了main_arena（但同样此时arena为空，里面没有内容！）的地址后对环境变量有一个遍历，试图找到"MALLOC_"变量，然而我跟踪的时候并没有，所以这个while循环里的所有代码都不会得到执行因此都省略了2333，还有后面的一个if也不满足条件，然后对\_\_malloc_initialize_hook区域有一个判断，类似一开始的\_\_malloc_hook，如果有内容，就调用之（pwn手们有新思路了吗），最后把\_\_malloc_initialized置1返回，流程回到\_\_libc_malloc：</font></br>

```C
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with anothe
```

&emsp;&emsp;<font size=2>arena_get定义如下：</font></br>

```C
#define arena_get(ptr, size) do { \
      ptr = thread_arena;                                                     \
      arena_lock (ptr, size);                                                 \
  } while (0)

```

&emsp;&emsp;<font size=2>ar_ptr被设置为了thread_arena，thread_arena我们之前看到过已经被赋值为了main_arena的地址，然后调用了_int_malloc，事实上这个才是堆块分配的主要逻辑：</font></br>

```C
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

  const char *errstr = NULL;

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size traps (returning 0) request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  checked_request2size (bytes, nb);

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
        alloc_perturb (p, bytes);
      return p;
    }
```

&emsp;&emsp;<font size=2>函数非常大，我们慢慢分析，该函数接受两个参数，一个是malloc参数size，还有一个就是之前去的的thread_arena，checked_request2size定义如下：</font></br>

```C
#define checked_request2size(req, sz)                             \
  if (REQUEST_OUT_OF_RANGE (req)) {                                           \
      __set_errno (ENOMEM);                                                   \
      return 0;                                                               \
    }                                                                         \
  (sz) = request2size (req);

#define REQUEST_OUT_OF_RANGE(req)                                 \
  ((unsigned long) (req) >=                                                   \
   (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))
#define MALLOC_ALIGN_MASK      (MALLOC_ALIGNMENT - 1)
#define SIZE_SZ                (sizeof(INTERNAL_SIZE_T))

#define offsetof(type,ident) ((size_t)&(((type*)0)->ident))
```

&emsp;&emsp;<font size=2>定义有些多，req就是我们申请的大小，sz就是经过计算或者说经过对齐的最终申请大小。其中的    INTERNAL_SIZE_T 其实就是size_t，SIZE_SZ在64位下是8，MALLOC_ALIGNMENT也就是0x10，因此MALLOC_ALIGN_MASK就是0xF。可以看如下源码注释：</font></br>

> /*
>   MALLOC_ALIGNMENT is the minimum alignment for malloc'ed chunks.
>   It must be a power of two at least 2 * SIZE_SZ, even on machines
>   for which smaller alignments would suffice. It may be defined as
>   larger than this though. Note however that code and data structures
>   are optimized for the case of 8-byte alignment.
> */

&emsp;&emsp;<font size=2>offsetof是一个非常巧妙的宏，可以获得任何结构体中的成员的偏移。因此MIN_CHUNK_SIZE是fd_nextsize在malloc_chunk结构中的偏移，也就是0x20。MINSIZE（64位下）就是0x20，所以request2size宏就可以理解了，根据这个算法，如果申请一个0x29~0x38大小的堆块，最终会返还一个0x40大小的堆块，而0x39～0x48，就会返还一个0x50大小的堆块，以此类推。因为`& ~MALLOC_ALIGN_MASK`这个对齐掩码的操作，不可能出现最后4个bit不为0的情况，都是0x10的整数倍。这时候我们已经得到正确的堆块大小了，继续往下看：</font></br>

```C
  checked_request2size (bytes, nb);

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      //...
    }

  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
  {
        //...
  }
```

&emsp;&emsp;<font size=2>事实上，因为我们是第一次分配，所以get_max_fast()返回的是0，因此无论第一次我们分配什么大小的堆块都不可能进入这个if。接下来我们先看看如下定义：</font></br>

```C
#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)

#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
```

&emsp;&emsp;<font size=2>我们已经知道MALLOC_ALIGNMENT为0x10，所以MIN_LARGE_SIZE可以很轻易的计算得出是0x400，我们申请的堆块经过计算为0x110，因此满足这个smallbin的条件，看如下gdb跟踪信息：</font></br>

```
 R15  0x0
 RBP  0x110
 RSP  0x7fffffffdb10 —▸ 0x7ffff7a92810 (ptmalloc_init) ◂— mov    eax, dword ptr [rip + 0x33e92e]
 RIP  0x7ffff7a8ec40 (_int_malloc+192) ◂— cmp    rbp, 0x3ff
────────────────────────────────────────[ DISASM ]─────────────────────────────────────────
   0x7ffff7a8ebb9 <_int_malloc+57>     test   rdi, rdi
   0x7ffff7a8ebbc <_int_malloc+60>     mov    qword ptr [rsp + 8], rsi
   0x7ffff7a8ebc1 <_int_malloc+65>     je     _int_malloc+2213 <0x7ffff7a8f425>
 
   0x7ffff7a8ebc7 <_int_malloc+71>     cmp    rbp, qword ptr [rip + 0x344c2a] <0x7ffff7dd37f8>
   0x7ffff7a8ebce <_int_malloc+78>     ja     _int_malloc+192 <0x7ffff7a8ec40>
    ↓
 ► 0x7ffff7a8ec40 <_int_malloc+192>    cmp    rbp, 0x3ff
   0x7ffff7a8ec47 <_int_malloc+199>    ja     _int_malloc+294 <0x7ffff7a8eca6>
 
   0x7ffff7a8ec49 <_int_malloc+201>    mov    eax, ebp
   0x7ffff7a8ec4b <_int_malloc+203>    shr    eax, 4
```

&emsp;&emsp;<font size=2>cmp rbp，0x3ff就是smallbin比较（经过编译器优化），我们继续看源码：</font></br>

```C
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          
```

&emsp;&emsp;<font size=2>进入if循环后，还有几个宏操作，我们先来看其定义：</font></br>

```C
#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
```

&emsp;&emsp;<font size=2>在64位系统下SMALLBIN_WIDTH就是16，因此这个smallbin_index返回的就是`0x110>>4=0x11`，bin_at定义如下：</font></br>

```C
#define bin_at(m, i) \
  (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))                           \
             - offsetof (struct malloc_chunk, fd))
```

&emsp;&emsp;<font size=2>m为传入的参数av，也就是malloc_state结构的main_arena，bins就是里面的普通堆块，简言之，就是计算得到了我们申请的堆块的大小应该在bins数组里的位置，然后减去偏移，猜测应该是让指针指向堆块的头部而不是fd的位置（程序中malloc返回的指针都是指向的fd，因为数据从fd开始写入，而不是从头部，因为这样输入会覆盖pre_size和size）。mbinptr和last的定义如下：</font></br>

```C
typedef struct malloc_chunk *mbinptr;

#define last(b)      ((b)->bk)
```

&emsp;&emsp;<font size=2>所以其根据index得到bins里的堆块后，检查这个堆块的bk指针是否指向自己，在这里因为main_arena都是空的，所以bk指针为0，因此不是指向自己，所以if条件被满足，而且victim作为bk指针的内容，自然也是0，所以`malloc_consolidate`函数被调用了：</font></br>

```C
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              //...
            }
        }
    }

```

&emsp;&emsp;<font size=2>malloc_consolidate：</font></br>

```C
static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;
  mchunkptr       bck;
  mchunkptr       fwd;

  /*
    If max_fast is 0, we know that av hasn't
    yet been initialized, in which case do so below
  */

  if (get_max_fast () != 0) {
    //...
  }
  else {
    malloc_init_state(av);
    check_malloc_state(av);
  }
}

```

&emsp;&emsp;<font size=2>之前我们提到过，get_max_fast()位置为0，因此进入else内部执行了，先来看`malloc_init_state`：</font></br>

```C
static void
malloc_init_state (mstate av)
{
  int i;
  mbinptr bin;

  /* Establish circular links for normal bins */
  for (i = 1; i < NBINS; ++i)
    {
      bin = bin_at (av, i);
      bin->fd = bin->bk = bin;
    }

#if MORECORE_CONTIGUOUS
  if (av != &main_arena)
#endif
  set_noncontiguous (av);
  if (av == &main_arena)
    set_max_fast (DEFAULT_MXFAST);
  av->flags |= FASTCHUNKS_BIT;

  av->top = initial_top (av);
}
```

&emsp;&emsp;<font size=2>相关定义如下：</font></br>

```C
typedef struct malloc_chunk *mbinptr;
#define NBINS             128
#define set_max_fast(s) \
  global_max_fast = (((s) == 0)                                               \
                     ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))//0x80
#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST     (64 * SIZE_SZ / 4)				//128
#endif

#define initial_top(M)              (unsorted_chunks (M))
#define unsorted_chunks(M)          (bin_at (M, 1))
```

&emsp;&emsp;<font size=2>也就是说直到malloc_init_state这个inline函数结束，所有的bins数组里面都被初始化填上了内容，并且global_max_fast也根据计算被设置为了0x80，这也是fastbin为啥最大只有0x80大小的原因。main_arena的flags置位，并且top堆块也被设置后，malloc_consolidate的初始化工作就结束了（但不知道为啥后面的check_malloc_state函数没有得到执行，这是我gdb跟踪时发现的）。</font></br>

&emsp;&emsp;<font size=2>那么这篇文章还是就讲到这吧，看了一下接下来分配堆块的地方比较长，本节讲了初始化的工作，应该也足够好好消化了。</font></br>