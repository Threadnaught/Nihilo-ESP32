#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "../include/api.h"

NIH_EXPORT(testFunc, param){
	char* x = (char*) malloc(50);
	strcpy(x, "This is malloc'd: ");
	strcpy(x+strlen(x), param);
	return x;
}
