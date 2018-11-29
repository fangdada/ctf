#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{

	void *p1,*p2,*p3,*p4,*p5;
	void *p6,*p7,*p8,*p9,*p10;
	long long* ptr;

	p1=malloc(0xf8);
	p2=malloc(0xf8);
	p3=malloc(0xf8);
	p4=malloc(0xf8);
	p5=malloc(0xf8);
	p6=malloc(0xf8);
	p7=malloc(0xf8);
	p8=malloc(0xf8);

	p9=malloc(0xf8);
	p10=malloc(0xf8);

	free(p9);
	free(p10);
	free(p1);
	free(p2);
	free(p3);
	free(p4);
	free(p5);
	printf("now the tcache struct is full\n");
	
	printf("these free bins will be regarded as smallbins and \n");
	printf("they will be consolidated\n");
	free(p6);
	free(p7);
	free(p8);

	malloc(0xf8);
	malloc(0xf8);
	malloc(0xf8);
	malloc(0xf8);
	malloc(0xf8);
	malloc(0xf8);
	malloc(0xf8);
	printf("now new alloc will be spilted from small bin\n");

	p1=malloc(0xf8);
	long long libc_base=*(long long*)p1-0x3ebf90;
	printf("so we can leak libc base by show p1:%llx\n",libc_base);
	free(p1);



	return 0;
}
