#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stderr,0,2,0);
	setvbuf(stdout,0,2,0);
}

int main()
{
	void *p0,*p1,*p2,*p3,*p4;
	long long *ptr;

	setbufs();

	mallopt(-6,0);
	p1=malloc(0x100);
	p2=malloc(0x100);

	free(p1);
	free(p2);

	p1=malloc(0x100);
	printf("libc leak:(0x%llx)\n",*(long long*)p1);
	free(p1);

	p0=malloc(0x100);
	p1=malloc(0x1000);

	mallopt(-6,0xcc);
	p2=calloc(1,0x100);
	p3=calloc(1,0x100);
	p4=calloc(1,0x100);

	// free p1 first cause FIFO unsortedbin 
	free(p1);
	free(p3);
	
	// unsortedbin 0x1000 added to largebin
	// so the fd_nextsize and bk_nextsize is set
	p3=calloc(1,0x100);

	// clear chunk
	free(p4);
	free(p3);
	free(p2);
	free(p0);

	mallopt(-6,0);
	p1=malloc(0x110); // 0x10 larger than previous size 0x100 to leak fd_nextsize

	p2=malloc(0x100);
	printf("chunk leak:(0x%llx)\n",*(long long*)p2);



	/*
	mallopt(-6,0xcc);
	p2=calloc(1,0x800);
	calloc(1,0x20);
	free(p2);

	p2=calloc(1,0x400);
	*/


	return 0;
}
