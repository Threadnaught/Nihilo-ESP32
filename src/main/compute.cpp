#include "Nihilo.h"

#include "wasm3.h"
#include "m3_env.h"
#include "m3_api_defs.h"
#include "root.wasm.h"
#include "esp_err.h"

//THESE FUNCTIONS ARE UNSAFE, WASM3 DOES NOT CURRENTLY BOUNDS-CHECK

locker<list<key_value_pair<IM3Runtime, char*>>*> all_params(new list<key_value_pair<IM3Runtime, char*>>());
locker<list<key_value_pair<IM3Runtime, char*>>*> all_rets(new list<key_value_pair<IM3Runtime, char*>>());

char* popPair(list<key_value_pair<IM3Runtime, char*>>* list, IM3Runtime target){
	for(int i = 0; i < list->count(); i++){
		auto kvp = list->peek(i);
		if (kvp.key == target){
			return list->pop(i).value;
		}
	}
	return NULL;
}

m3ApiRawFunction(nih_get_param)
{
	m3ApiGetArg(u32, param)
	list<key_value_pair<IM3Runtime, char*>>* p = *all_params.acquire();
	strncpy((char*)m3ApiOffsetToPtr(param), popPair(p, runtime), 1000);
	all_params.release();
	m3ApiSuccess();
}

m3ApiRawFunction(nih_return)
{
	m3ApiGetArg(u32, param)
	char* src = (char*)m3ApiOffsetToPtr(param);
	size_t len = strnlen(src, 999); //truncates return value at 1000 chars
	char* dest = (char*)malloc(len+1);
	memcpy(dest, src, len+1);
	list<key_value_pair<IM3Runtime, char*>>* r = *all_rets.acquire();
	r->add(key_value_pair<IM3Runtime, char*>(runtime, dest));
	all_rets.release();
	ESP_LOGI(nih, "mid-return RAM:%i", esp_get_free_heap_size());
	m3ApiSuccess();
}

//calling function has responsibility for cleaning up both parameter and return value!!!
char* run_wasm(char* param)
{
	ESP_LOGI(nih, "start RAM:%i", esp_get_free_heap_size());

	IM3Environment env = m3_NewEnvironment ();

	ESP_LOGI(nih, "pre-runtime RAM:%i", esp_get_free_heap_size());
	IM3Runtime runtime = m3_NewRuntime (env, 1024, NULL);
	
	ESP_LOGI(nih, "post-runtime RAM:%i", esp_get_free_heap_size());

	list<key_value_pair<IM3Runtime, char*>>* params = *all_params.acquire();
	params->add(key_value_pair<IM3Runtime, char*>(runtime, param));
	all_params.release();

	IM3Module module;
	M3Result result = m3_ParseModule (env, &module, (uint8_t*)root_opt_wasm, root_opt_wasm_len-1);
	if(result) ESP_LOGE(nih, "result 1:%s", result);

	ESP_LOGI(nih, "post-modparse RAM:%i", esp_get_free_heap_size());

	result = m3_LoadModule (runtime, module);
	if(result) ESP_LOGE(nih, "result 2:%s", result);
	result = m3_LinkRawFunction (module, "nih", "getParam", "v(*)", &nih_get_param);
	if(result) ESP_LOGE(nih, "result 3:%s", result);
	ESP_LOGI(nih, "mid-link RAM:%i", esp_get_free_heap_size());
	result = m3_LinkRawFunction (module, "nih", "setReturn", "v(*)", &nih_return);
	if(result) ESP_LOGE(nih, "result 3:%s", result);
	ESP_LOGI(nih, "post-link RAM:%i", esp_get_free_heap_size());
	IM3Function func;
	result = m3_FindFunction (&func, runtime, "wrapper_testFunc");
	if(result) ESP_LOGE(nih, "result 4:%s", result);
	ESP_LOGI(nih, "post-found function:%i", esp_get_free_heap_size());
	const char* char_args[] = { NULL };
	result = m3_CallWithArgs (func, 0, char_args);
	if(result) ESP_LOGE(nih, "result 5:%s", result);
	ESP_LOGI(nih, "post-exec RAM:%i", esp_get_free_heap_size());

	list<key_value_pair<IM3Runtime, char*>>* rets = *all_rets.acquire();
	char* ret = popPair(rets, runtime);
	all_rets.release();

	ESP_LOGI(nih, "pre-free RAM:%i", esp_get_free_heap_size());
	m3_FreeRuntime(runtime);
	m3_FreeEnvironment(env);

	ESP_LOGI(nih, "end RAM:%i", esp_get_free_heap_size());

	return ret;
}