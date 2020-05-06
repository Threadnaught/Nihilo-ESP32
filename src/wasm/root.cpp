#include "../include/api.h"

NIH_VOID(entry, param){
	logStr("entry");
}

NIH_VOID(RPC, param){
	logStr("RPC Called!");
}

NIH_VOID(success, param){
	logStr("success");
	if(param[0] != 0)
		logStr(param);
}

NIH_VOID(fail, param){
	logStr("error");
	if(param != nullptr) 
		logStr(param);
}
