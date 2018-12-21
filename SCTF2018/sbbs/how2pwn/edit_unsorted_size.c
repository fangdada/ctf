#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p1,*p2,*p3,*p4,*p5;
	long long *ptr;
	long long fake_size=0x656c;
	long long align_size=fake_size&0xfffffffffffffff8;

	p1=malloc(0x200);
	p2=malloc(0x20);

	free(p1);
	// expand unsortedbin'size
	ptr=(long long*)p1-1;
	*ptr=0x656c;

	// fake the pre_size to avoid broken
	ptr=(long long)p1+align_size-0x10;
	*ptr=align_size;

	malloc(0x200);
	p1=malloc(0x20);

	printf("now p1(%p) and p2(%p) is opverlapped\n",p1,p2);

	return 0;
}
