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
	puts("watch");
	malloc(0x60);

	return 0;
}
