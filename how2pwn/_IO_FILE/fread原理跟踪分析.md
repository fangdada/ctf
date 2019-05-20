&emsp;&emsp;<font size=2>上次我们已经跟踪了一遍fopen的原理，这次我们来跟踪分析一下fread从文件描述符读取内容的过程。这有助于我们进一步了解_IO_FILE结构体，源码如下：</font></br>

```C
weak_alias (_IO_fread, fread)
#define _IO_size_t size_t

#ifdef IO_DEBUG
//...
#else
# define CHECK_FILE(FILE, RET) COERCE_FILE (FILE)
#endif

# define COERCE_FILE(FILE) /* Nothing */

_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t bytes_requested = size * count;
  _IO_size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    //...
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
```

&emsp;&emsp;<font size=2>fread的别名是_IO_fread，其参数接受了目标地址，读取粒度，数量以及一个FILE*变量。CHECK_FILE事实上什么都不做，\_IO_acquire_lock也不是我们关心的东西（顾名思义就行，用锁互斥），然后控制流就进入了_IO_sgetn，其源码如下：</font></br>

```C
_IO_size_t
_IO_sgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n);
}
libc_hidden_def (_IO_sgetn)
```

&emsp;&emsp;<font size=2>其直接调用了另一个函数\_IO_XSGETN，这个函数我们非常眼熟，这是一个在vtable中注册的函数（但我不是指他是通过vtable调用的）：</font></br>

```C
  __xsgetn = 0x7ffff7a85ec0 <__GI__IO_file_xsgetn>
```

&emsp;&emsp;<font size=2>其源码如下：</font></br>

```C
_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  _IO_size_t want, have;
  _IO_ssize_t count;
  char *s = data;

  want = n;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
        {
          free (fp->_IO_save_base);
          fp->_flags &= ~_IO_IN_BACKUP;
        }
      _IO_doallocbuf (fp);
    }
```

&emsp;&emsp;<font size=2>显然我们文件指针的_IO_FILE刚经过初始化，\_IO_buf_base和\_IO_save_base肯定都是0的，所以会调用\_IO_doallocbuf分配缓冲区：</font></br>

```C
#define _IO_UNBUFFERED 2

void
_IO_doallocbuf (_IO_FILE *fp)
{
  if (fp->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED) || fp->_mode > 0)
    if (_IO_DOALLOCATE (fp) != EOF)
      return;
  _IO_setb (fp, fp->_shortbuf, fp->_shortbuf+1, 0);
}
libc_hidden_def (_IO_doallocbuf)
```

&emsp;&emsp;<font size=2>我们的fp->_flags为0xfbad2488，满足了if的第一个条件因此调用了\_IO_DOALLOCATE，这一次是通过vtable调用的，调用方式如下：</font></br>

```
  __doallocate = 0x7ffff7a7a180 <__GI__IO_file_doallocate>, 
  
 ► 0x7ffff7a8858e <_IO_doallocbuf+46>    mov    rdi, rbx
   0x7ffff7a88591 <_IO_doallocbuf+49>    call   qword ptr [rax + 0x68]
```

&emsp;&emsp;<font size=2>其源码如下：</font></br>

```C
int
_IO_file_doallocate (_IO_FILE *fp)
{
  _IO_size_t size;
  char *p;
  struct stat64 st;

#ifndef _LIBC
  //...
#endif

  size = _IO_BUFSIZ;
  if (fp->_fileno >= 0 && __builtin_expect (_IO_SYSSTAT (fp, &st), 0) >= 0)
    {
```

&emsp;&emsp;<font size=2>显然我们的fileno之前已经设置为了open返回的文件描述符了，其值为3，随后再次通过vtable调用了\_IO_SYSSTAT，其定义如下：</font></br>

```C
#define _IO_SYSSTAT(FP, BUF) JUMP1 (__stat, FP, BUF)

int
_IO_file_stat (_IO_FILE *fp, void *st)
{
  return __fxstat64 (_STAT_VER, fp->_fileno, (struct stat64 *) st);
}
libc_hidden_def (_IO_file_stat)

```

&emsp;&emsp;<font size=2>在这里我们就不继续深入了，\_\_fxstat64直接使用了调用号为5的syscall系统调用SYS_fstat，一般都能成功且返回值为0，因此控制流返回到\_IO_file_doallocate，if的条件被满足，所以进入if内部：</font></br>

```C
      if (S_ISCHR (st.st_mode))
        {
          //...
        }
#if _IO_HAVE_ST_BLKSIZE
      if (st.st_blksize > 0)
        size = st.st_blksize;
#endif
    }
  p = malloc (size);
  if (__glibc_unlikely (p == NULL))
    return EOF;
  _IO_setb (fp, p, p + size, 1);
  return 1;
}

```

&emsp;&emsp;<font size=2>此时st结构如下：</font></br>

```
pwndbg> p *(struct stat64*)0x7fffffffdae0
$35 = {
  st_dev = 2049, 
  st_ino = 3839400, 
  st_nlink = 1, 
  st_mode = 33204, 
  st_uid = 1000, 
  st_gid = 1000, 
  __pad0 = 0, 
  st_rdev = 0, 
  st_size = 6, 
  st_blksize = 4096, 
  st_blocks = 8, 
  st_atim = {
    tv_sec = 1558184925, 
    tv_nsec = 710595774
  }, 
  st_mtim = {
    tv_sec = 1558106735, 
    tv_nsec = 272930919
  }, 
  st_ctim = {
    tv_sec = 1558106735, 
    tv_nsec = 272930919
  }, 
  __glibc_reserved = {0, 0, 0}
}

```

&emsp;&emsp;<font size=2>所以st.st_blksize会传给size，然后作为malloc的参数申请堆块，在这里会申请一个0x1000大小的堆块，_IO_setb的定义如下：</font></br>

```C
#define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */

void
_IO_setb (_IO_FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    //...
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    f->_flags &= ~_IO_USER_BUF;
  else
    //...
}
```

&emsp;&emsp;<font size=2>所以在这里根据传入的参数（b为堆块首地址，eb为堆块末地址，a为1），将f这个FILE指针的\_IO_buf_base设置为了b，\_IO_buf_end设置为了eb，然后去除了\_IO_USER_BUF标志位。这时我们的f指针如下：</font></br>

```
pwndbg> p *(struct _IO_FILE_plus*)0x602010
$39 = {
  file = {
    _flags = -72539000, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x602240 "", 
    _IO_buf_end = 0x603240 "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7ffff7dd2540 <_IO_2_1_stderr_>, 
    _fileno = 3, 
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
```

&emsp;&emsp;<font size=2>接下来控制流一直返回到了_IO_new_file_xsputn：</font></br>

```C
  while (want > 0)
    {
      have = fp->_IO_read_end - fp->_IO_read_ptr;
      if (want <= have)
        {
          //...
        }
      else
        {
          if (have > 0)
            {
              //...
            }

          /* Check for backup and repeat */
          if (_IO_in_backup (fp))
            {
              /...
            }
        
```

&emsp;&emsp;<font size=2>\_IO_in_backup的定义如下：</font></br>

```C
#define _IO_in_backup(fp) ((fp)->_flags & _IO_IN_BACKUP)
#define _IO_IN_BACKUP 0x100
```

&emsp;&emsp;<font size=2>我们的flags之前看过了，为0xfbad2488，因此if不满足，继续往下：</font></br>

```C
          /* If we now want less than a buffer, underflow and repeat
             the copy.  Otherwise, _IO_SYSREAD directly to
             the user buffer. */
          if (fp->_IO_buf_base
              && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
            {
              if (__underflow (fp) == EOF)
                break;

              continue;
            }

```

&emsp;&emsp;<font size=2>显然这一条if就可以满足了，want就是我们之前在fread那里计算得来的参数`1*4=4`，所以调用了\__underflow：</font></br>

```C
# define _IO_vtable_offset(THIS) (THIS)->_vtable_offset


int
__underflow (_IO_FILE *fp)
{
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  //...
#endif

  if (fp->_mode == 0)
    _IO_fwide (fp, -1);
  if (_IO_in_put_mode (fp))
    //...
```

&emsp;&emsp;<font size=2>相关定义如下：</font></br>

```C
#  define _IO_fwide(__fp, __mode) \
  ({ int __result = (__mode);                                                 \
     if (__result < 0 && ! _IO_fwide_maybe_incompatible)                      \
       {                                                                      \
         if ((__fp)->_mode == 0)                                              \
           /* We know that all we have to do is to set the flag.  */          \
           (__fp)->_mode = -1;                                                \
         __result = (__fp)->_mode;                                            \
       }                                                                      \
     else if (__builtin_constant_p (__mode) && (__mode) == 0)                 \
       //...
     else                                                                     \
       //...
     __result; })
# endif

#define _IO_in_put_mode(_fp) ((_fp)->_flags & _IO_CURRENTLY_PUTTING)
#define _IO_CURRENTLY_PUTTING 0x800
```

&emsp;&emsp;<font size=2>\_IO_fwide这个宏看上去难以理解，但实际上就是把我们的fp文件指针中的\_mode设置为了-1，然后就结束了，第二个if的\_IO_in_put_mode宏测试了我们的flags中的\_IO_CURRENTLY_PUTTING标志位，在我们的情况下（0xfbad2488）显然是不成立的，因此继续往下看：</font></br>

```C
#define _IO_have_markers(fp) ((fp)->_markers != NULL)
#define _IO_have_backup(fp) ((fp)->_IO_save_base != NULL)

  if (fp->_IO_read_ptr < fp->_IO_read_end)
    //...
  if (_IO_in_backup (fp))
    {
      //...
    }
  if (_IO_have_markers (fp))
    {
      //...
    }
  else if (_IO_have_backup (fp))
    //...
  return _IO_UNDERFLOW (fp);
}


```

&emsp;&emsp;<font size=2>后续的if也全都不满足，最终调用\_IO_UNDERFLOW：</font></br>

```C
# define _IO_new_file_underflow _IO_file_underflow
#define _IO_NO_READS 4 /* Reading not allowed */

int
_IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;

  if (fp->_flags & _IO_NO_READS)
    {
      //...
    }
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    //...

  if (fp->_IO_buf_base == NULL)
    {
      //...
    }
  
  /* Flush all line buffered files before reading. */
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
      //...
    }
  _IO_switch_to_get_mode (fp);

```

&emsp;&emsp;<font size=2>这个函数也十分类似，一开始的if都不满足，直接调用了\_IO_switch_to_get_mode：</font></br>

```C
int
_IO_switch_to_get_mode (_IO_FILE *fp)
{
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    //...
  if (_IO_in_backup (fp))
    //...
  else
    {
      fp->_IO_read_base = fp->_IO_buf_base;
      if (fp->_IO_write_ptr > fp->_IO_read_end)
        fp->_IO_read_end = fp->_IO_write_ptr;
    }
  fp->_IO_read_ptr = fp->_IO_write_ptr;

  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = fp->_IO_read_ptr;

  fp->_flags &= ~_IO_CURRENTLY_PUTTING;
  return 0;
}
libc_hidden_def (_IO_switch_to_get_mode)
```

&emsp;&emsp;<font size=2>这里对fp指针的一系列成员进行了设置，并且去掉了\_IO_CURRENTLY_PUTTING标志位，然后控制流返回到\_IO_file_underflow：</font></br>

```C
  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
                       fp->_IO_buf_end - fp->_IO_buf_base);
```

&emsp;&emsp;<font size=2>同样对fp的成员进行了很多设置，然后调用了vtable里的\_IO_SYSREAD（第三个参数注意一下，程序是一次读取了堆块大小的字节），在看这个函数之前我们先看一下此时fp指针的状况：</font></br>

```
pwndbg> p *(struct _IO_FILE_plus*)0x602010
$51 = {
  file = {
    _flags = -72539000, 
    _IO_read_ptr = 0x602240 "", 
    _IO_read_end = 0x602240 "", 
    _IO_read_base = 0x602240 "", 
    _IO_write_base = 0x602240 "", 
    _IO_write_ptr = 0x602240 "", 
    _IO_write_end = 0x602240 "", 
    _IO_buf_base = 0x602240 "", 
    _IO_buf_end = 0x603240 "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7ffff7dd2540 <_IO_2_1_stderr_>, 
    _fileno = 3, 
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
    _mode = -1, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
```

&emsp;&emsp;<font size=2>\_IO_SYSRAED就是vtable中的\_\_read，其别名又是_IO_file_read：</font></br>

```C
#define _IO_FLAGS2_NOTCANCEL 2

_IO_ssize_t
_IO_file_read (_IO_FILE *fp, void *buf, _IO_ssize_t size)
{
  return (__builtin_expect (fp->_flags2 & _IO_FLAGS2_NOTCANCEL, 0)
          ? read_not_cancel (fp->_fileno, buf, size)
          : read (fp->_fileno, buf, size));
}
libc_hidden_def (_IO_file_read)
```

&emsp;&emsp;<font size=2>我们的fp->_flags2为0，因此会调用read_not_cancel，其定义如下：</font></br>

```C
/* Uncancelable read.  */
#define read_not_cancel(fd, buf, n) \
  __read_nocancel (fd, buf, n)
#define __read_nocancel(fd, buf, len) \
  INLINE_SYSCALL (read, 3, fd, buf, len)
```

&emsp;&emsp;<font size=2>其实到了这里就可以知道已经进入系统调用了，跟fopen类似，fopen调用了系统open，fread调用系统read，这是肯定的。因此读取完了之后控制流返回到了_IO_new_file_underflow：</font></br>

```C
# define _IO_pos_BAD ((_IO_off64_t) -1)

  if (count <= 0)
  {
      //...
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      //...
    }
  if (fp->_offset != _IO_pos_BAD)
    //...
  return *(unsigned char *) fp->_IO_read_ptr;
}
```

&emsp;&emsp;<font size=2>\_IO_pos_BAD其实就是-1，而我们的_offset也是-1，因此if不执行，underflow函数终于执行完毕，返回到了\_IO_file_xsgetn：</font></br>

```C
              if (__underflow (fp) == EOF)
                break;

              continue;
            }
```

&emsp;&emsp;<font size=2>\_\_unferflow返回的是_IO_read_ptr的第一个字节，我们的文件是有内容的，不为EOF，因此continue返回到了while：</font></br>

```C
  while (want > 0)
    {
      have = fp->_IO_read_end - fp->_IO_read_ptr;
      if (want <= have)
        {
          memcpy (s, fp->_IO_read_ptr, want);
          fp->_IO_read_ptr += want;
          want = 0;
        }
      else
        {
          //...
        }
      }
  return n - want;
}

```

&emsp;&emsp;<font size=2>根据want参数，也就是我们调用fread时计算的`size*count`，把_IO_FILE的缓冲区的内容复制到我们调用fread的第一个参数（目标缓冲区），增加\_IO_read_ptr，然后最终返回我们读取的字节数，控制流终于回到fread：</font></br>

```C
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
libc_hidden_def (_IO_fread)

```

&emsp;&emsp;<font size=2>最后就是释放锁，函数返回，返回值就是fread的参数count，程序回到main。</font></br>

&emsp;&emsp;<font size=2>所以对fread的分析也结束了，内容也不少啊。</font></br>