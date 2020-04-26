#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "../include/api.h"

NIH_EXPORT(testFunc, param){
	char* test;
	mallocWasm((void**)&test, 10);
	readString("a.b.c", &test);
	return test;
}
