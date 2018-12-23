#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setbufs(){
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
	ptr=(long long*)p1;

	for(int i=0;i<64;i++)
		*(ptr+i)=0x91;

	// use gdb to debug it
	// turn off the aslr
	puts("watch");

	ptr=(long long*)p1-1;
	*ptr=0x111;

	free((void*)p1);
	free((void*)0x602030);

	malloc(0x100);

	return 0;
}
