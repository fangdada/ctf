> 环境：glibc2.23

&emsp;&emsp;<font size=2>在Linux下我们可能听说过open函数比较多，open函数由POSIX实现，但C语言标准实现了一个叫fopen的函数，其返回值不是一个可供系统调用的文件句柄，而是一个_IO_FILE指针，本节我们就主要剖析一下C是如何利用这个文件指针来进行文件读写的。老样子先写一个hello，world：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>

char buf[10];

int main()
{ 
	FILE* f=fopen("flag","r");
	fread(buf,1,4,f);
	fclose(f);

	printf("%s\n",buf);

	return 0;
}

```

&emsp;&emsp;<font size=2>从这个源码文件开始看起`libio/iofopen`：</font></br>

```C
# define _IO_new_fopen fopen

_IO_FILE *
_IO_new_fopen (const char *filename, const char *mode)
{
  return __fopen_internal (filename, mode, 1);
}

```

&emsp;&emsp;<font size=2>可以看到我们使用的fopen实际上就是\_IO_new_fopen函数的别名，其内部又直接调用了\_\_fopen_internal，还加入了第三个参数1，`__fopen_internal`：</font></br>

```C
_IO_FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.file._lock = &new_f->lock;
#endif
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
#else
  //...
#endif
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  _IO_file_init (&new_f->fp);
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.vtable = NULL;
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}
```

&emsp;&emsp;<font size=2>接下来补充一下与上面代码相关的定义：</font></br>

```C
typedef void _IO_lock_t;

/* Extra data for wide character streams.  */
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;        /* Current read pointer */
  wchar_t *_IO_read_end;        /* End of get area. */
  wchar_t *_IO_read_base;       /* Start of putback+get area. */
  wchar_t *_IO_write_base;      /* Start of put area. */
  wchar_t *_IO_write_ptr;       /* Current put pointer. */
  wchar_t *_IO_write_end;       /* End of put area. */
  wchar_t *_IO_buf_base;        /* Start of reserve area. */
  wchar_t *_IO_buf_end;         /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;       /* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;     /* Pointer to first valid character of
                                   backup area */
  wchar_t *_IO_save_end;        /* Pointer to end of non-current get area. */
  
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  
  wchar_t _shortbuf[1];
  
  const struct _IO_jump_t *_wide_vtable;
};

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

struct _IO_FILE {
  int _flags;           /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else 
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};

struct _IO_FILE_complete_plus
{
  struct _IO_FILE_complete file;
  const struct _IO_jump_t *vtable;
};


```

&emsp;&emsp;<font size=2>定义有点长，但我们不用立马把他们都记住，只需要先看一遍就行了，我们慢慢分析(\_IO_FILE事实上是\_IO_FILE_complete，plus也同理，以后都这么称呼)，先把locked_FILE结构体的lock赋给了fp指针中的\_IO_FILE结构体的\_lock，然后调用了_IO_no_init：</font></br>

```C
void
_IO_no_init (_IO_FILE *fp, int flags, int orientation,
             struct _IO_wide_data *wd, const struct _IO_jump_t *jmp)
{
  _IO_old_init (fp, flags);
  
```

&emsp;&emsp;<font size=2>其又首先调用了_IO_old_init：</font></br>

```C
#define _IO_MAGIC 0xFBAD0000
#define _IO_lock_init(_name) \
  ((void) ((_name) = (_IO_lock_t) _IO_lock_initializer))
typedef void _IO_lock_t;
#define _IO_lock_initializer { LLL_LOCK_INITIALIZER, 0, NULL }


void
_IO_old_init (_IO_FILE *fp, int flags)
{
  fp->_flags = _IO_MAGIC|flags;
  fp->_flags2 = 0;
  fp->_IO_buf_base = NULL;
  fp->_IO_buf_end = NULL;
  fp->_IO_read_base = NULL;
  fp->_IO_read_ptr = NULL;
  fp->_IO_read_end = NULL;
  fp->_IO_write_base = NULL;
  fp->_IO_write_ptr = NULL;
  fp->_IO_write_end = NULL;
  fp->_chain = NULL; /* Not necessary. */

  fp->_IO_save_base = NULL;
  fp->_IO_backup_base = NULL;
  fp->_IO_save_end = NULL;
  fp->_markers = NULL;
  fp->_cur_column = 0;
#if _IO_JUMPS_OFFSET
  fp->_vtable_offset = 0;
#endif
#ifdef _IO_MTSAFE_IO
  if (fp->_lock != NULL)
    _IO_lock_init (*fp->_lock);
#endif
}
```

&emsp;&emsp;<font size=2>\_IO_old_init初始化了fp的\_IO_FILE结构，其中_IO_lock_init相关定义太多太杂，只需要知道fp->\_lock被初始化为0就行了，flags在此处为0，_IO_MAGIC为0xfbad0000，这下你知道这个奇怪的数字是怎么来的吧，这就是magic。接下来控制流返回\_IO_no_init：</font></br>

```C
void
_IO_no_init (_IO_FILE *fp, int flags, int orientation,
             struct _IO_wide_data *wd, const struct _IO_jump_t *jmp)
{
  _IO_old_init (fp, flags);
  fp->_mode = orientation;
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  if (orientation >= 0)
    {
      fp->_wide_data = wd;
      fp->_wide_data->_IO_buf_base = NULL;
      fp->_wide_data->_IO_buf_end = NULL;
      fp->_wide_data->_IO_read_base = NULL;
      fp->_wide_data->_IO_read_ptr = NULL;
      fp->_wide_data->_IO_read_end = NULL;
      fp->_wide_data->_IO_write_base = NULL;
      fp->_wide_data->_IO_write_ptr = NULL;
      fp->_wide_data->_IO_write_end = NULL;
      fp->_wide_data->_IO_save_base = NULL;
      fp->_wide_data->_IO_backup_base = NULL;
      fp->_wide_data->_IO_save_end = NULL;

      fp->_wide_data->_wide_vtable = jmp;
    }
  else
    /* Cause predictable crash when a wide function is called on a byte
       stream.  */
    //...
#endif
  fp->_freeres_list = NULL;
}
```

&emsp;&emsp;<font size=2>剩余代码就是初始化了fp->_IO_wide_data这个结构体，其中比较不一样的是jmp，这个\_IO_jump_t结构的变量似乎是系统之前生成的，我们就不溯源了。随后控制流从\_IO_no_init返回到了\_\_fopen_internal：</font></br>

```C
#define _IO_JUMPS(THIS) (THIS)->vtable

  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  _IO_file_init (&new_f->fp);
```

&emsp;&emsp;<font size=2>设置了fp的vtable，\_IO_file_jumps也是一个\_IO_jump_t的结构，跟上面那个不太一样，上面那个是\_wide_data的，下面这个就像是普通的，这两个变量有一点点差别（\_IO_wfile_jumps就是之前的jmp）：</font></br>

```
pwndbg> p _IO_wfile_jumps
$13 = {
  __dummy = 0, 
  __dummy2 = 0, 
  __finish = 0x7ffff7a869c0 <_IO_new_file_finish>, 
  __overflow = 0x7ffff7a818a0 <__GI__IO_wfile_overflow>, 
  __underflow = 0x7ffff7a807d0 <__GI__IO_wfile_underflow>, 
  __uflow = 0x7ffff7a7ef60 <__GI__IO_wdefault_uflow>, 
  __pbackfail = 0x7ffff7a7ed00 <__GI__IO_wdefault_pbackfail>, 
  __xsputn = 0x7ffff7a81c70 <__GI__IO_wfile_xsputn>, 
  __xsgetn = 0x7ffff7a85ec0 <__GI__IO_file_xsgetn>, 
  __seekoff = 0x7ffff7a80df0 <__GI__IO_wfile_seekoff>, 
  __seekpos = 0x7ffff7a88a00 <_IO_default_seekpos>, 
  __setbuf = 0x7ffff7a85430 <_IO_new_file_setbuf>, 
  __sync = 0x7ffff7a81b10 <__GI__IO_wfile_sync>, 
  __doallocate = 0x7ffff7a7b660 <_IO_wfile_doallocate>, 
  __read = 0x7ffff7a861a0 <__GI__IO_file_read>, 
  __write = 0x7ffff7a85b70 <_IO_new_file_write>, 
  __seek = 0x7ffff7a85970 <__GI__IO_file_seek>, 
  __close = 0x7ffff7a85340 <__GI__IO_file_close>, 
  __stat = 0x7ffff7a85b60 <__GI__IO_file_stat>, 
  __showmanyc = 0x7ffff7a89af0 <_IO_default_showmanyc>, 
  __imbue = 0x7ffff7a89b00 <_IO_default_imbue>
}
pwndbg> p _IO_file_jumps
$14 = {
  __dummy = 0, 
  __dummy2 = 0, 
  __finish = 0x7ffff7a869c0 <_IO_new_file_finish>, 
  __overflow = 0x7ffff7a87730 <_IO_new_file_overflow>, 
  __underflow = 0x7ffff7a874a0 <_IO_new_file_underflow>, 
  __uflow = 0x7ffff7a88600 <__GI__IO_default_uflow>, 
  __pbackfail = 0x7ffff7a89980 <__GI__IO_default_pbackfail>, 
  __xsputn = 0x7ffff7a861e0 <_IO_new_file_xsputn>, 
  __xsgetn = 0x7ffff7a85ec0 <__GI__IO_file_xsgetn>, 
  __seekoff = 0x7ffff7a854c0 <_IO_new_file_seekoff>, 
  __seekpos = 0x7ffff7a88a00 <_IO_default_seekpos>, 
  __setbuf = 0x7ffff7a85430 <_IO_new_file_setbuf>, 
  __sync = 0x7ffff7a85370 <_IO_new_file_sync>, 
  __doallocate = 0x7ffff7a7a180 <__GI__IO_file_doallocate>, 
  __read = 0x7ffff7a861a0 <__GI__IO_file_read>, 
  __write = 0x7ffff7a85b70 <_IO_new_file_write>, 
  __seek = 0x7ffff7a85970 <__GI__IO_file_seek>, 
  __close = 0x7ffff7a85340 <__GI__IO_file_close>, 
  __stat = 0x7ffff7a85b60 <__GI__IO_file_stat>, 
  __showmanyc = 0x7ffff7a89af0 <_IO_default_showmanyc>, 
  __imbue = 0x7ffff7a89b00 <_IO_default_imbue>
}
pwndbg> 
```

&emsp;&emsp;<font size=2>随后调用了\_IO_file_init，其别名又是\_IO_new_file_init：</font></br>

```C
# define _IO_new_file_init _IO_file_init
# define _IO_pos_BAD ((_IO_off64_t) -1)
#define CLOSED_FILEBUF_FLAGS \
  (_IO_IS_FILEBUF+_IO_NO_READS+_IO_NO_WRITES+_IO_TIED_PUT_GET)
#define _IO_IS_FILEBUF 0x2000
#define _IO_NO_READS 4 /* Reading not allowed */
#define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */

void
_IO_new_file_init (struct _IO_FILE_plus *fp)
{
  /* POSIX.1 allows another file handle to be used to change the position
     of our file descriptor.  Hence we actually don't know the actual
     position before we do the first fseek (and until a following fflush). */
  fp->file._offset = _IO_pos_BAD;
  fp->file._IO_file_flags |= CLOSED_FILEBUF_FLAGS;

  _IO_link_in (fp);
  fp->file._fileno = -1;
}

```

&emsp;&emsp;<font size=2>其中\_IO_off64_t牵扯的也有些多，而且事实上放入fp->file._offset的就是一个-1，因此不挖掘了，随后调用了\_IO_link_in函数：</font></br>

```C
#define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/


void
_IO_link_in (struct _IO_FILE_plus *fp)
{
  if ((fp->file._flags & _IO_LINKED) == 0)
    {
      fp->file._flags |= _IO_LINKED;
#ifdef _IO_MTSAFE_IO
      _IO_cleanup_region_start_noarg (flush_cleanup);
      _IO_lock_lock (list_all_lock);
      run_fp = (_IO_FILE *) fp;
      _IO_flockfile ((_IO_FILE *) fp);
#endif
      fp->file._chain = (_IO_FILE *) _IO_list_all;
      _IO_list_all = fp;
      ++_IO_list_all_stamp;
#ifdef _IO_MTSAFE_IO
      _IO_funlockfile ((_IO_FILE *) fp);
      run_fp = NULL;
      _IO_lock_unlock (list_all_lock);
      _IO_cleanup_region_end (0);
#endif
    }
}
```

&emsp;&emsp;<font size=2>这里操作有些冗杂，只需要知道关键部分就行了，这里把\_IO_list_all设置为了这个fp指针，然后fp->_chain（也就是\_IO_FILE链表的下一个节点设置为了原来的\_IO_list_all指向的结构：\_IO_2_1_stderr\_。这是程序在main函数之前就初始化好的）。\_IO_link_in函数执行完了后fp结构体如下：</font></br>

```
pwndbg> p *(struct _IO_FILE_plus*)0x602010
$18 = {
  file = {
    _flags = -72538996, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7ffff7dd2540 <_IO_2_1_stderr_>, 
    _fileno = 0, 
    _flags2 = 0, 
    _old_offset = 0, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x6020f0, 
    _offset = -1, 
    _codecvt = 0x0, 
    _wide_data = 0x602100, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
pwndbg> p & _IO_list_all
$19 = (struct _IO_FILE_plus **) 0x7ffff7dd2520 <_IO_list_all>
pwndbg> x/xg 0x7ffff7dd2520
0x7ffff7dd2520 <_IO_list_all>:	0x0000000000602010
pwndbg> 
```

&emsp;&emsp;<font size=2>\_IO_list_all是\_IO_FILE链表的头部，可以看到我们的文件指针已经被插入到了\_IO_list_all的头部，fp->_chain指向的就是下一个\_IO_FILE结构体。接下来控制流返回到\_\_fopen_internal：</font></br>

```C
#if  !_IO_UNIFIED_JUMPTABLES
  //...
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

# define _IO_new_file_fopen _IO_file_fopen
```

&emsp;&emsp;<font size=2>\_IO_new_file_fopen就是\_IO_file_fopen的别名，这个函数源码如下：</font></br>

```C
#define _IO_file_is_open(__fp) ((__fp)->_fileno != -1)
#define O_RDONLY        0       /* Open read-only.  */
#define _IO_NO_WRITES 8 /* Writing not allowd */

_IO_FILE *
_IO_new_file_fopen (_IO_FILE *fp, const char *filename, const char *mode,
                    int is32not64)
{
  int oflags = 0, omode;
  int read_write;
  int oprot = 0666;
  int i;
  _IO_FILE *result;
#ifdef _LIBC
  const char *cs;
  const char *last_recognized;
#endif

  if (_IO_file_is_open (fp))
    //...
  switch (*mode)
    {
    case 'r':
      omode = O_RDONLY;
      read_write = _IO_NO_WRITES;
      break;
      //...
    }
#ifdef _LIBC
  last_recognized = mode;
#endif
  for (i = 1; i < 7; ++i)
    {
      switch (*++mode)
        {
        case '\0':
          break;
        //...
        }
      break;
    }
  
  result = _IO_file_open (fp, filename, omode|oflags, oprot, read_write,
                          is32not64);
```

&emsp;&emsp;<font size=2>显然在我们之前初始化的时候fp的->\_fileno被初始化为-1，这代表文件未打开的状态，控制流继续往下，switch里判断的mode其实指向的是我们使用fopen传入的字符串参数，也就是"r"、"w"，"a"或者"rw"之类的，我们在这里传入的为"r"，因此omode被设置为了0，read_write被设置为了8。后面又因为我们只传入了一个"r"，所以第二个字节就是"\0"，所以直接跳出循环。再次调用了\_IO_file_open，但这一次不是\_IO_new_file_open，而是_IO_file_open：</font></br>

```C
#define _IO_FLAGS2_NOTCANCEL 2

_IO_FILE *
_IO_file_open (_IO_FILE *fp, const char *filename, int posix_mode, int prot,
               int read_write, int is32not64)
{
  int fdesc;
#ifdef _LIBC
  if (__glibc_unlikely (fp->_flags2 & _IO_FLAGS2_NOTCANCEL))
    //...
  else
    fdesc = open (filename, posix_mode | (is32not64 ? 0 : O_LARGEFILE), prot);
#else
  //...
#endif
```

&emsp;&emsp;<font size=2>其检查了fp->\_flags2的\_IO_FLAGS2_NOTCANCEL标志位，而我们的_flags2为0，因此不会触发，后续调用了open，而open的别名是open64，然后open64又是\_\_libc_open64的别名，所以事实上调用的是__libc_open64，而is32not64其实就是从\_\_open_internal一直传参下来的，为1，因此最终posix_mode为0，prot为0666（八进制）：</font></br>

```C
#  define open open64
weak_alias (__libc_open64, open64)

int
__libc_open64 (const char *file, int oflag, ...)
{
  int mode = 0;

  if (__OPEN_NEEDS_MODE (oflag))
    {
      va_list arg;
      va_start (arg, oflag);
      mode = va_arg (arg, int);
      va_end (arg);
    }

  return SYSCALL_CANCEL (open, file, oflag | O_LARGEFILE, mode);
}

#define SINGLE_THREAD_P __builtin_expect (__local_multiple_threads == 0, 1)
#define SYSCALL_CANCEL(...) \
  ({                                                                         \
    long int sc_ret;                                                         \
    if (SINGLE_THREAD_P)                                                     \
      sc_ret = __SYSCALL_CALL (__VA_ARGS__);                                 \
    else                                                                     \
      {                                                                      \
        //...                             \
      }                                                                      \
    sc_ret;                                                                  \
  })

```

&emsp;&emsp;<font size=2>__libc_open64中的if被编译器优化了，因此直接是SYSCALL_CANCEL宏定义，根据gdb跟踪的反汇编来看：</font></br>

```
   0x7ffff7b04030 <open64>                cmp    dword ptr [rip + 0x2d2709], 0 <0x7ffff7dd6740>
   0x7ffff7b04037 <open64+7>              jne    open64+25 <0x7ffff7b04049>
 
   0x7ffff7b04039 <__open_nocancel>       mov    eax, 2
   0x7ffff7b0403e <__open_nocancel+5>     syscall 
   0x7ffff7b04040 <__open_nocancel+7>     cmp    rax, -0xfff
 ► 0x7ffff7b04046 <__open_nocancel+13>    jae    open64+73 <0x7ffff7b04079>
 
   0x7ffff7b04048 <__open_nocancel+15>    ret    
    ↓
   0x7ffff7a86ace <_IO_file_open+142>     mov    r8d, dword ptr [rsp + 0xc]
   
pwndbg> x/g 0x7ffff7b04037+0x2d2709
0x7ffff7dd6740 <__libc_multiple_threads>:	0x0000000000000000
```

&emsp;&emsp;<font size=2>再深入就是系统调用了，其检查了__libc_multiple_threads是否为 0，在我们这里显然是0，因此直接使用系统调用号为2的syscall使用了SYSCALL_OPEN，后来看了一下open64就是Linux系统调用open的别名（也就是说直接调用了Linux的系统调用），然后返回值就是3，这是一个文件句柄。然后控制流返回到了\_IO_file_open：</font></br>

&emsp;&emsp;<font size=2>那么本节就讲到这了，内容有点出乎意料的多，fopen都还没讲完233。</font></br>

