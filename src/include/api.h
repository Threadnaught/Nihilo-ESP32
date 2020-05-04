//MODIFIED FROM https://github.com/wasm3/wasm3-arduino/blob/master/wasm_apps/cpp/arduino_api.h

#pragma once

#include <stdint.h>
#include <stdlib.h>

#define WASM_IMPORT(MODULE,NAME)		__attribute__((import_module(MODULE))) __attribute__((import_name(NAME)))

extern "C" {
	WASM_IMPORT("nih", "setReturn") void setReturn (char* ret);
	WASM_IMPORT("nih", "getParam") void getParam(char** param);
	WASM_IMPORT("nih", "mallocWasm") void mallocWasm(void** target, uint32_t size);
	WASM_IMPORT("nih", "writeString") void writeString(const char* path, const char* value);
	WASM_IMPORT("nih", "readString") void readString(const char* path, char** target);
	WASM_IMPORT("nih", "knownIds") int knownIds(unsigned char** IdsOut, int include_local, int include_non_local);
	WASM_IMPORT("nih", "log") void logStr(const char* tolog);
}

#define NIH_VOID(NAME, PARAMNAME) \
	void NAME(char* PARAMNAME); /*declare function so wrapper can use it*/\
	extern "C" __attribute__((used)) __attribute__((visibility ("default"))) \
	void wrapper_##NAME(){char* param; getParam(&param); NAME(param); } /*make wrapper around function which handles param and return */\
	void NAME(char* PARAMNAME) /*allow developer to implement their own function*/

#define NIH_CHARS(NAME, PARAMNAME) \
	char* NAME(char* PARAMNAME); /*declare function so wrapper can use it*/\
	extern "C" __attribute__((used)) __attribute__((visibility ("default"))) \
	void wrapper_##NAME(){char* param; getParam(&param); setReturn(NAME(param)); } /*make wrapper around function which handles param and return */\
	char* NAME(char* PARAMNAME) /*allow developer to implement their own function*/

//int to string:
char* decstr(int input){
	char buf[50];
	for(int i = 0; i < 49; i++)buf[i] = 0;
	bool neg = input < 0;
	if(neg) input *= -1;
	int i = 0;
	for(; input > 0; i++){
		buf[i] = '0' + (input % 10);
		input /= 10;
	}
	if(neg){
		buf[i] = '-';
		i++;
	}
	char* ret;
	mallocWasm((void**)&ret, i+1);
	int k = 0;
	for(int j = i; j >= 0; j--){
		if(buf[j] != '\0'){
			ret[k] = buf[j];
			k++;
		}
	}
	return ret;
}