> 环境：glibc2.23

&emsp;&emsp;<font size=2>上一节我们分析过了一遍fread读取文件的过程，那么文件操作结束后自然要用fclose关闭文件里，这一节我们就好好分析一下fclose的原理，其源码如下：</font></br>

```C
# define _IO_new_fclose fclose
# define CHECK_FILE(FILE, RET) COERCE_FILE (FILE)
# define COERCE_FILE(FILE) /* Nothing */
#define _IO_file_flags _flags
#define _IO_IS_FILEBUF 0x2000

int
_IO_new_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  //...
#endif

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);

```

&emsp;&emsp;<font size=2>同样CHECK_FILE什么也不做，然后检查了\_IO_IS_FILEBUF的标志位，我们的fp->_flags为0xfbad2488，显然是满足的，因此进入\_IO_un_link，这个函数比较琐碎，只挑其中有用的看一下就行了：</font></br>

```C
      else if (fp == _IO_list_all)
        {
          _IO_list_all = (struct _IO_FILE_plus *) _IO_list_all->file._chain;
          ++_IO_list_all_stamp;
        }
      fp->file._flags &= ~_IO_LINKED;
```

&emsp;&emsp;<font size=2>我们的文件fp指针被从_IO_FILE链表中脱链，\_IO_list_all重新指向\_IO_2_1_stderr\_，并且fp->\_flags的\_IO_LINKED标志位被取消，返回到fclose，\_IO_acquire_lock我们也跳过，继续看：</font></br>

```C
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
```

&emsp;&emsp;<font size=2>调用了\_IO_file_close_it：</font></br>

```C
# define _IO_new_file_close_it _IO_file_close_it
#define _IO_file_is_open(__fp) ((__fp)->_fileno != -1)
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_CURRENTLY_PUTTING 0x800

int
_IO_new_file_close_it (_IO_FILE *fp)
{
  int write_status;
  if (!_IO_file_is_open (fp))
    return EOF;

  if ((fp->_flags & _IO_NO_WRITES) == 0
      && (fp->_flags & _IO_CURRENTLY_PUTTING) != 0)
    //...
  else
    write_status = 0;
  
  _IO_unsave_markers (fp);

```

&emsp;&emsp;<font size=2>此时我们的flags为0xfbad2408，因此if不满足，write_status被置0，然后调用了\_IO_unsave_markers：</font></br>

```C
#define _IO_have_backup(fp) ((fp)->_IO_save_base != NULL)

void
_IO_unsave_markers (_IO_FILE *fp)
{
  struct _IO_marker *mark = fp->_markers;
  if (mark)
    {
      //...
    }

  if (_IO_have_backup (fp))
    //...
}
libc_hidden_def (_IO_unsave_markers)
```

&emsp;&emsp;<font size=2>什么都没做就返回了，回到fclose继续看：</font></br>

```C
  int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
                      ? _IO_SYSCLOSE (fp) : 0);
```

&emsp;&emsp;<font size=2>fp->_flags2仍然为0，因此调用了vtable的\_IO_SYSCLOSE，其实就是\_IO_file_close：</font></br>

```C
#define _IO_SYSCLOSE(FP) JUMP0 (__close, FP)

int
_IO_file_close (_IO_FILE *fp)
{
  /* Cancelling close should be avoided if possible since it leaves an
     unrecoverable state behind.  */
  return close_not_cancel (fp->_fileno);
}
libc_hidden_def (_IO_file_close)
```

&emsp;&emsp;<font size=2>这个close_not_cancel就是直接到了系统调用号为3的SYS_close（肯定绕不过系统）系统调用，其返回值为0，代表成功关闭，然后控制流返回到_IO_new_file_close_it：</font></br>

```C
  /* Free buffer. */
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  if (fp->_mode > 0)
    {
		  //...
    }
#endif
  _IO_setb (fp, NULL, NULL, 0);
  _IO_setg (fp, NULL, NULL, NULL);
  _IO_setp (fp, NULL, NULL);

```

&emsp;&emsp;<font size=2>fp->_mode为-1，因此不进入if，调用了\_IO_setb：</font></br>

```C
void
_IO_setb (_IO_FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base);
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    //...
  else
    f->_flags |= _IO_USER_BUF;
}
libc_hidden_def (_IO_setb)

```

&emsp;&emsp;<font size=2>这一次释放了我们第一次调用fread分配的0x1000大小的临时缓冲区，然后把\_IO_buf_base和end置0，并设置了f->_flags的\_IO_USER_BUF标志位后返回：</font></br>

```C
  _IO_setg (fp, NULL, NULL, NULL);
  _IO_setp (fp, NULL, NULL);
  _IO_un_link ((struct _IO_FILE_plus *) fp);
```

&emsp;&emsp;<font size=2>他们的宏定义如下：</font></br>

```C
#define _IO_setg(fp, eb, g, eg)  ((fp)->_IO_read_base = (eb),\
        (fp)->_IO_read_ptr = (g), (fp)->_IO_read_end = (eg))
#define _IO_setp(__fp, __p, __ep) \
       ((__fp)->_IO_write_base = (__fp)->_IO_write_ptr \
        = __p, (__fp)->_IO_write_end = (__ep))
```

&emsp;&emsp;<font size=2>他们把\_IO_read_\*和\_IO_write\_\*都置0，然后调用了\_IO_un_link：</font></br>

```C
void
_IO_un_link (struct _IO_FILE_plus *fp)
{
  if (fp->file._flags & _IO_LINKED)
    {
      //...
    }
}
```

&emsp;&emsp;<font size=2>这一次直接返回了，没有任何操作。_IO_new_file_close_it的最后部分如下：</font></br>

```C
#define _IO_pos_BAD ((_IO_off64_t)(-1))

  fp->_flags = _IO_MAGIC|CLOSED_FILEBUF_FLAGS;
  fp->_fileno = -1;
  fp->_offset = _IO_pos_BAD;
  
  return close_status ? close_status : write_status;
}
```

&emsp;&emsp;<font size=2>设置了fp->_flags的标志位，把句柄（文件描述符）和\_offset设置为-1，close_status就是之前调用\_IO_SYSCLOSE的返回值，也就是SYS_close系统调用的返回值0，因此返回值为write_status，write_status之前我们看到过了为0，因此返回值为0代表成功。然后控制流返回到了fclose：</font></br>

```C
  _IO_release_lock (fp);
  _IO_FINISH (fp);
```

&emsp;&emsp;<font size=2>跳过\_IO_release_lock，我们看\_IO_FINISH：</font></br>

```C
#define _IO_FINISH(FP) JUMP1 (__finish, FP, 0)
#define _IO_file_is_open(__fp) ((__fp)->_fileno != -1)

void
_IO_new_file_finish (_IO_FILE *fp, int dummy)
{
  if (_IO_file_is_open (fp))
    {
      _IO_do_flush (fp);
      if (!(fp->_flags & _IO_DELETE_DONT_CLOSE))
        _IO_SYSCLOSE (fp);
    }
  _IO_default_finish (fp, 0);
}
libc_hidden_ver (_IO_new_file_finish, _IO_file_finish)

```

&emsp;&emsp;<font size=2>显然我们的fp文件指针已经关闭，因此不满足if条件，调用了\_IO_default_finish：</font></br>

```C
/* The way the C++ classes are mapped into the C functions in the
   current implementation, this function can get called twice! */

void
_IO_default_finish (_IO_FILE *fp, int dummy)
{
  struct _IO_marker *mark;
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    {
      //...
    }

  for (mark = fp->_markers; mark != NULL; mark = mark->_next)
    //...

  if (fp->_IO_save_base)
    {
      //...
    }

  _IO_un_link ((struct _IO_FILE_plus *) fp);

#ifdef _IO_MTSAFE_IO
   //...
#endif
}
libc_hidden_def (_IO_default_finish)

```

&emsp;&emsp;<font size=2>事实上我在gdb跟踪的时候\_IO_un_link没被调用，可能被编译器优化掉了？不管这个，返回到fclose继续往下看：</font></br>

```C
#define _IO_have_backup(fp) ((fp)->_IO_save_base != NULL)

  if (fp->_mode > 0)
    {
      //...
    }
  else
    {
      if (_IO_have_backup (fp))
        //...
    }
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
}
```

&emsp;&emsp;<font size=2>fp为我们自己的文件指针，当然不属于任何一个std结构，因此承载fp的堆块被free了，至此我们的文件指针算是彻彻底底被清理了，然后fclose也返回了，分析也结束了，这个比较简单，所以最后来一张被free之前的快照吧:D</font></br>

```
pwndbg> p *(struct _IO_FILE_plus*)0x602010
$69 = {
  file = {
    _flags = -72539124, 
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
    _fileno = -1, 
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
pwndbg> 
```

