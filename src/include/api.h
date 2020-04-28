//MODIFIED FROM https://github.com/wasm3/wasm3-arduino/blob/master/wasm_apps/cpp/arduino_api.h

#pragma once

#include <stdint.h>
#include <stdlib.h>

//#define WASM_EXPORT						extern "C" __attribute__((used)) __attribute__((visibility ("default")))
//#define WASM_EXPORT_AS(NAME)			WASM_EXPORT __attribute__((export_name(NAME)))
#define WASM_IMPORT(MODULE,NAME)		__attribute__((import_module(MODULE))) __attribute__((import_name(NAME)))
//#define WASM_CONSTRUCTOR				__attribute__((constructor))

extern "C" {
	WASM_IMPORT("nih", "setReturn") void setReturn (char* ret);
	WASM_IMPORT("nih", "getParam") void getParam(char** param);
	WASM_IMPORT("nih", "mallocWasm") void mallocWasm(void** target, uint32_t size);
	WASM_IMPORT("nih", "writeString") void writeString(const char* path, const char* value);
	WASM_IMPORT("nih", "readString") void readString(const char* path, char** target);
	WASM_IMPORT("nih", "knownIds") void knownIds(char** IdsOut, int include_local, int include_non_local);
}

#define NIH_EXPORT(NAME, PARAMNAME) \
	char* NAME(char* PARAMNAME); /*declare function so wrapper can use it*/\
	extern "C" __attribute__((used)) __attribute__((visibility ("default"))) \
	void wrapper_##NAME(){char* param; getParam(&param); setReturn(NAME(param)); /*freeeee*/ } /*make wrapper around function which handles param and return */\
	char* NAME(char* PARAMNAME) /*allow developer to implement their own function*/

