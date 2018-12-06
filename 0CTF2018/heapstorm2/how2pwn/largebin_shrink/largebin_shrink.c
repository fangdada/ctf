#include <stdio.h>
#include <stdlib.h>

void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
}

int main()
{
	void *p0,*p1,*p2,*p3,*p4,*p5;
	long long* ptr;

	setbufs();

	// #define M_MXFAST 1
	mallopt(1,0);	// forbid fastbin

	p0=malloc(0x20);
	p1=malloc(0x530);
	p2=malloc(0x20);
	p3=malloc(0x20);

	ptr=(long long)p1+0x4f0;
	*ptr=0x500;	// fake the pre_size
	free(p1);
	ptr=(long long*)p1-1;
	*ptr=0x500;

	p4=malloc(0x20);// unlink and bypass check
	p5=malloc(0x4c0); // chunk overlapped

	free(p4);
	free(p2);

	puts("watch");
	malloc(0x20);
	p1=malloc(0x4c0);

	printf("now p1(%p) and p5(%p) is overlapped\n",p1,p5);





	return 0;
}
