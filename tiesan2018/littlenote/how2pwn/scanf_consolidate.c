#include <stdio.h>
#include <stdlib.h>

void setbufs()
{
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	setvbuf(stdin,0,2,0);
}

int main()
{
	void *p1,*p2,*p3,*p4;
	long long *ptr;
	long long var=0;

	setbufs();

	p1=malloc(0x20);
	p2=malloc(0x20);
	p3=malloc(0x20);
	p4=malloc(0x20);
	malloc(0);

	free(p1);
	free(p2);
	free(p3);
	free(p4);

	scanf("%d",&var);
	printf("%u\n",var);
	


	return 0;
}
