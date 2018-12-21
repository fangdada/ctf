#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p1,*p2,*p3,*p4;

	// FIFO unsortedbin list
	p1=malloc(0x400);
	malloc(0x20);
	p2=malloc(0x400);
	malloc(0x20);
	p3=malloc(0x400);
	malloc(0x20);

	free(p1);
	free(p2);
	free(p3);

	printf("the new malloc 0x400(%p) will be p1(%p)\n",malloc(0x400),p1);



	return 0;
}
