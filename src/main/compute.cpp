#include "Nihilo.h"

#include "wasm3.h"
#include "m3_env.h"
#include "m3_api_defs.h"
#include "root.wasm.h"
#include "esp_err.h"

//THESE FUNCTIONS ARE UNSAFE, WASM3 DOES NOT CURRENTLY BOUNDS-CHECK
char funcbuf[1000];
m3ApiRawFunction(nih_get_param)
{
	m3ApiGetArg(u32, param)
	memcpy((char*)m3ApiOffsetToPtr(param), funcbuf, sizeof(funcbuf));
	m3ApiSuccess();
}
m3ApiRawFunction(nih_return)
{
	m3ApiGetArg(u32, param)
	memcpy(funcbuf, (char*)m3ApiOffsetToPtr(param), sizeof(funcbuf));
	m3ApiSuccess();
}


void run_wasm()
{
	strcpy(funcbuf, "god I hate you");

	IM3Environment env = m3_NewEnvironment ();
	IM3Runtime runtime = m3_NewRuntime (env, 10*1024, NULL);
	
	IM3Module module;
	M3Result result = m3_ParseModule (env, &module, (uint8_t*)root_opt_wasm, root_opt_wasm_len-1);
	if(result) ESP_LOGE(nih, "result 1:%s", result);
	result = m3_LoadModule (runtime, module);
	if(result) ESP_LOGE(nih, "result 2:%s", result);
	result = m3_LinkRawFunction (module, "nih", "getParam", "v(*)", &nih_get_param);
	if(result) ESP_LOGE(nih, "result 3:%s", result);
	result = m3_LinkRawFunction (module, "nih", "setReturn", "v(*)", &nih_return);
	if(result) ESP_LOGE(nih, "result 3:%s", result);
	IM3Function func;
	result = m3_FindFunction (&func, runtime, "wrapper_testFunc");
	if(result) ESP_LOGE(nih, "result 4:%s", result);
	const char* char_args[] = { NULL };
	result = m3_CallWithArgs (func, 0, char_args);
	if(result) ESP_LOGE(nih, "result 5:%s", result);

	ESP_LOGI(nih, "ret: %s", funcbuf);
	
}