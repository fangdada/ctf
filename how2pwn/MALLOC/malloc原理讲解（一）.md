&emsp;&emsp;<font size=2>跟puts函数一样，首先我们写一个简单的hello,world式程序，然后用glibc2.23的源码参考配合gdb分析：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
	malloc(0x100);
	malloc(0x20);

	return 0;
}

```

&emsp;&emsp;<font size=2>首先malloc.c的5221行可以看到别名的定义：</font></br>

```C
strong_alias (__libc_free, __free) strong_alias (__libc_free, free)
strong_alias (__libc_malloc, __malloc) strong_alias (__libc_malloc, malloc)
```

&emsp;&emsp;<font size=2>因此malloc函数主体的源码如下：</font></br>

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

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    (void) mutex_unlock (&ar_ptr->mutex);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
```

&emsp;&emsp;<font size=2>首先定义了一个函数指针hook取得\_\_malloc_hook区域的内容，然后如果`hook!=0`，就会调用hook函数（这也是攻击\_\_malloc_hook思路的由来），否则继续往下执行，看arena_get的定义：</font></br>

```C
/* arena_get() acquires an arena and locks the corresponding mutex.
   First, try the one last locked successfully by this thread.  (This
   is the common case and handled with a macro for speed.)  Then, loop
   once over the circularly linked list of arenas.  If no arena is
   readily available, create a new one.  In this latter case, `size'
   is just a hint as to how much memory will be required immediately
   in the new arena. */
#define arena_get(ptr, size) do { \
      ptr = thread_arena;                                                     \
      arena_lock (ptr, size);                                                 \
  } while (0)

#define arena_lock(ptr, size) do {                                            \
      if (ptr && !arena_is_corrupt (ptr))                                     \
        (void) mutex_lock (&ptr->mutex);                                      \
      else                                                                    \
        ptr = arena_get2 ((size), NULL);                                      \
  } while (0)
```

&emsp;&emsp;<font size=2>thread_arena的定义如下：</font></br>

```C
//include/malloc.h
typedef struct malloc_state *mstate;
//**************************************

//malloc/malloc.c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
//**************************************

//malloc/arena.c
static __thread mstate thread_arena attribute_tls_model_ie;

```

&emsp;&emsp;<font size=2>所以在这里我先讲解一下这个arena，根据注释，每次malloc时都会获取当前线程的arena，也就是thread_arena，其结构就是malloc_state，malloc_state的定义又由一系列互斥数组链表等组成。mchunkptr定义如下：</font></br>

```C
typedef struct malloc_chunk* mchunkptr;
typedef struct malloc_chunk *mfastbinptr;

struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

```

&emsp;&emsp;<font size=2>代表每个线程堆块情况的malloc_state除去开头的互斥体和flags，接下来就是fastbinY数组，顾名思义其保存了fastbins，然后是top堆块，普通堆块bins和一个binmap，在对malloc分析时如果不深入系统原理的话我们只需要关注fastbins，top和bins这些堆块就行了。根据malloc_chunk的结构定义和注释，每个堆块在内存中形态如下：</font></br>

```C
    An allocated chunk looks like this:


    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if allocated            | |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                       |M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk                                     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              
              
              
    Free chunks are stored in circular doubly-linked lists, and look like this:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

&emsp;&emsp;<font size=2>为了方便理解，先放一张内存快照：</font></br>

```
pwndbg> x/20xg 0x602000
0x602000:	0x0000000000000000	0x0000000000000111
0x602010:	0x0000000000000000	0x0000000000000000
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
0x602110:	0x0000000000000000	0x0000000000000031
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
pwndbg> 
```

&emsp;&emsp;<font size=2>这是执行了`malloc(0x100);malloc(0x20);`后的结果，可以看到对于64位系统（小端排序），前8个字节为`Size of previous chunk`，但在这里因为没有前一个堆块（事实上如果存在pre_size，前一个堆块也得是freed状态）所以pre_size为0，第二个8字节为0x111，经过了计算，malloc的参数0x100+align_size+标志位。其中align_size和标识位是怎么来的我们在后续讲解。将这个0x100堆块free之后状态如下：</font></br>

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
0x602110:	0x0000000000000110	0x0000000000000030
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
pwndbg> 
```

&emsp;&emsp;<font size=2>可以看到0x100堆块的pre_size仍然为0，理由如上。而chunk的fd和bk指针被放上了两个奇怪的数据，但fd_nextsize和bk_nextsize没有（理由见malloc_chunk结构体定义的注释），原理我们也是后续讲解，比较显眼的是第二个0x20堆块的pre_size被置位了！而且本身的size从0x31变为了0x30！</font></br>

&emsp;&emsp;<font size=2>之前我们说过pre_size保存的是上一个堆块的size，所以在这里被置位非常容易理解，至于size里的标志位P，其义为pre_inuse，其原理我们先看看注释解释：</font></br>

> ​    The P (PREV_INUSE) bit, stored in the unused low-order bit of the
> ​    chunk size (which is always a multiple of two words), is an in-use
> ​    bit for the *previous* chunk.  If that bit is *clear*, then the
> ​    word before the current chunk size contains the previous chunk
> ​    size, and can be used to find the front of the previous chunk.
> ​    The very first chunk allocated always has this bit set,
> ​    preventing access to non-existent (or non-owned) memory. If
> ​    prev_inuse is set for any given chunk, then you CANNOT determine
> ​    the size of the previous chunk, and might even get a memory
> ​    addressing fault when trying to do so.

&emsp;&emsp;<font size=2>也就是说这个P标志位代表的不是chunk的size，而是一种flag，其意义就是上一个堆块是否为freed状态。如果是，P标志位就会被置位为0，不是就会置位为1，0x20堆块的P标志位被清空则意味着上一个堆块为freed状态（在我们的情况中正是如此）。</font></br>

&emsp;&emsp;<font size=2>因为malloc是一个非常庞大复杂的过程，所以我们就分多个章节讲解，本节就给大家一个chunk的大致意象，明白chunk在内存中的结构是怎么一回事，深刻的原理我们在后续章节进行解释。</font></br>
