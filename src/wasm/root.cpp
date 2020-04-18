#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "../include/api.h"

NIH_EXPORT(testFunc, param){
	char* x = (char*) malloc(50);
	snprintf(x, 50, "I this is malloc'd: %s", param);
	return x;
}
