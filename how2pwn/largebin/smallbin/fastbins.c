#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p1,*p2,*p3,*p4;
	long long *ptr;

	p1=malloc(0x60);
	p2=malloc(0x60);
	p3=malloc(0x60);

	free(p1);
	ptr=(long long*)p1;

	*ptr=(long long)p3-0x10;

	malloc(0x60);
	printf("new malloc will be overlapping with p3,\nnew: %p \t p3: %p\n",malloc(0x60),p3);




}
