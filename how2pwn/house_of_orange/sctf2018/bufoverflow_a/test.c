#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	void* p1,*p2,*p3,*p4;

	p1=malloc(0x100);
	p2=malloc(0x100);
	p3=malloc(0x100);
	p4=malloc(0x100);

	free(p1);
	free(p2);
	p1=malloc(0x100);
	p2=malloc(0x100);
	long long*ptr=(long long*)p3;
	ptr-=2;
	*ptr=0x220;
	ptr++;
	*ptr=0x110;
	free(p3);
	

	return 0;
}
