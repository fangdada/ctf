#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p1,*p2,*p3,*p4;
	long long*ptr;
	long long var=0;

	p1=malloc(0x78);
	p2=malloc(0x78);
	p3=malloc(0x78);

	free(p1);
	free(p1);

	p1=malloc(0x78);
	ptr=(long long*)p1;
	*ptr=&var;

	malloc(0x78);
	p4=malloc(0x78);
	ptr=(long long*)p4;
	*ptr=0x1111;

	printf("the var is written to :%llx\n",var);



	return 0;
}
