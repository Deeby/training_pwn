#include <stdio.h>

int main(){
	int a;
	unsigned int b;
	a = -5;
	b = -5;
	if(b  >= 0x5)
		b += 1;
	if(a >= 0xa)
		a += 1;
	
	printf("%d %d", a,b);
	return 0;

}