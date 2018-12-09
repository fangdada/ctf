#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p1,*p2,*p3,*p4;
	long long*ptr;

	ptr=(long long*)malloc(0)-1;
	printf("malloc(0); return the size of 0x%llx chunk.\n",*ptr);

	return 0;
}
