#include "../include/api.h"

NIH_VOID(entry, param){
	unsigned char* ids;
	int howmany = knownIds((unsigned char**)&ids, 1, 1);
	abort();
	logStr(decstr(howmany));
}

NIH_VOID(success, param){
	logStr("success");
}

NIH_VOID(error, param){
	logStr("error");
	if(param != nullptr) 
		logStr(param);
}