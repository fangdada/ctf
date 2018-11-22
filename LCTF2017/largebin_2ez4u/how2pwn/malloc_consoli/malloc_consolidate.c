#include <stdio.h>
#include <stdlib.h>

int main()
{
	void *p1,*p2,*p3,*p4,*p5;

	p1=malloc(0x78);
	malloc(0x20);
	p2=malloc(0x78);
	malloc(0x20);
	p3=malloc(0x78);
	malloc(0x20);
	p4=malloc(0x78);
	//malloc(0x20);

	free(p1);
	free(p2);
	free(p3);
	free(p4);

	printf("the nearby fastbin will be consolidated to largebin\n");
	printf("if a 20-size chunk was allocated, no nearby fastbin, so no consolidate.\n");
	malloc(0x3f0);



	return 0;
}
