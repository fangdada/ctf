#include <stdio.h>
#include <stdlib.h>

//FIFO smallbins alloc
int main()
{
	void *p1,*p2,*p3,*p4;
	long long*ptr;

	p1=malloc(0x78);
	malloc(0x20);
	p2=malloc(0x78);
	malloc(0x20);
	p3=malloc(0x78);
	malloc(0x20);

	free(p1);
	free(p2);
	free(p3);

	p4=malloc(0x3f0);

	printf("p1 fd:%llx \t\tbk:%llx\n",*(long long*)p1,*((long long*)p1+1));
	printf("p2 fd:%llx \t\tbk:%llx\n",*(long long*)p2,*((long long*)p2+1));
	printf("p3 fd:%llx \tbk:%llx\n",*(long long*)p3,*((long long*)p3+1));

	ptr=(long long*)p2;
	//*ptr=0;
	*(ptr+1)=0;
	printf("\nedit p2 \t\tbk->0\n");

	p3=malloc(0x78);
	printf("new malloc 0x78 will be p3\n");
	printf("p3 fd:%llx \tbk:%llx\n\n",*(long long*)p3,*((long long*)p3+1));

	printf("p1 fd:%llx \t\tbk:%llx\n",*(long long*)p1,*((long long*)p1+1));
	printf("p2 fd:%llx \tbk:%llx\n",*(long long*)p2,*((long long*)p2+1));
	printf("p3 fd:%llx \tbk:%llx\n",*(long long*)p3,*((long long*)p3+1));


	return 0;
}
