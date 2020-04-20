//MODIFIED FROM https://github.com/wasm3/wasm3-arduino/blob/master/wasm_apps/cpp/arduino_api.h

#pragma once

#include <stdint.h>
#include <stdlib.h>

//#define WASM_EXPORT						extern "C" __attribute__((used)) __attribute__((visibility ("default")))
//#define WASM_EXPORT_AS(NAME)			WASM_EXPORT __attribute__((export_name(NAME)))
#define WASM_IMPORT(MODULE,NAME)		__attribute__((import_module(MODULE))) __attribute__((import_name(NAME)))
//#define WASM_CONSTRUCTOR				__attribute__((constructor))

extern "C" {
	WASM_IMPORT("nih", "paramSize") int paramSize ();
	WASM_IMPORT("nih", "getParam") void getParam (char* param);
	WASM_IMPORT("nih", "setReturn") void setReturn (char* ret);
}

#define NIH_EXPORT(NAME, PARAMNAME) \
	char* NAME(char* PARAMNAME); /*declare function so wrapper can use it*/\
	extern "C" __attribute__((used)) __attribute__((visibility ("default"))) void wrapper_##NAME(){char* param = (char*)malloc(paramSize()); getParam(param); setReturn(NAME(param)); delete param;} /*make wrapper around function which handles param and return */\
	char* NAME(char* PARAMNAME) /*allow developer to implement their own function*/

