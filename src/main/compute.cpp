#include "Nihilo.h"

#include "wasm3.h"
#include "m3_env.h"
#include "m3_api_defs.h"
#include "esp_err.h"

#define heap_offset 0x8000//how far is heap from stack

locker<list<key_value_pair<IM3Runtime, char*>>*> all_params(new list<key_value_pair<IM3Runtime, char*>>());
locker<list<key_value_pair<IM3Runtime, char*>>*> all_rets(new list<key_value_pair<IM3Runtime, char*>>());
locker<list<key_value_pair<IM3Runtime, char*>>*> all_ids(new list<key_value_pair<IM3Runtime, char*>>());

char* popPair(list<key_value_pair<IM3Runtime, char*>>* list, IM3Runtime target){
	for(int i = 0; i < list->count(); i++){
		auto kvp = list->peek(i);
		if (kvp.key == target){
			return list->pop(i).value;
		}
	}
	return NULL;
}
void* malloc_runtime(size_t size, IM3Runtime r){//pray to god no one uses over 0x8000 stack address
	char* heap_origin = ((char*)(r->memory.mallocated + 1))+heap_offset;
	uint16_t* already_allocated = (uint16_t*)heap_origin;
	char* ret = heap_origin + *already_allocated + sizeof(uint16_t);
	*already_allocated += size;
	return (void*)ret;
}
void free_runtime(){
	//there is no escape
}

m3ApiRawFunction(nih_get_param)
{
	m3ApiGetArg(u32, param)
	list<key_value_pair<IM3Runtime, char*>>* params = *all_params.acquire();
	char* cur_pair = popPair(params, runtime);
	all_params.release();
	char* target = (char*)malloc_runtime(strlen(cur_pair)+1, runtime);
	strcpy(target, cur_pair);
	u32* y = (u32*)m3ApiOffsetToPtr(param);//offset to x
	*y = m3ApiPtrToOffset(target);
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
	popPair(r, runtime);//pop if runtime already has returned (cheeky)
	r->add(key_value_pair<IM3Runtime, char*>(runtime, dest));
	all_rets.release();
	m3ApiSuccess();
}
m3ApiRawFunction(nih_malloc)//allocate to my heap
{
	m3ApiGetArg(u32, param)
	m3ApiGetArg(u32, size)
	char* target = (char*)malloc_runtime(size, runtime);
	u32* y = (u32*)m3ApiOffsetToPtr(param);//offset to x
	*y = m3ApiPtrToOffset(target);
	m3ApiSuccess();
}
void id_to_fname(char* fname, IM3Runtime runtime){
	list<key_value_pair<IM3Runtime, char*>>* ids = *all_ids.acquire();
	char* id = popPair(ids, runtime);
	ids->add(key_value_pair<IM3Runtime, char*>(runtime, id));
	all_ids.release();
	fname[0] = '/';
	bytes_to_hex((unsigned char*)id, ID_len, fname+1);
	strcpy(fname+strlen(fname), ".json");
}
m3ApiRawFunction(nih_write_string)//passed path and value
{
	m3ApiGetArg(u32, path)
	m3ApiGetArg(u32, value)
	char* path_ptr = (char*)m3ApiOffsetToPtr(path);
	if(strlen(path_ptr) > 99)
		return m3Err_mallocFailed;//most relevant seeming error
	char path_str[100];
	strcpy(path_str, path_ptr);
	char fname[40];
	id_to_fname(fname, runtime);
	cJSON* json = file_to_json(fname);
	cJSON* data = cJSON_GetObjectItemCaseSensitive(json, "Data");
	
	char* prev = path_str;
	for(char* cur = path_str; *cur != '\0'; cur++)
		if(*cur == '.'){
			*cur = '\0';
			cJSON* next = cJSON_GetObjectItemCaseSensitive(data, prev);
			if(!cJSON_IsObject(next)){//if next is not an object, delete it
				cJSON_DeleteItemFromObjectCaseSensitive(data, prev);
				next = nullptr;
			}
			if(!next){//if there is no next, create it
				next = cJSON_CreateObject();
				cJSON_AddItemToObject(data, prev, next);
			}
			data = next;//prepare for next iteration
			prev = cur + 1;
		}
	cJSON* todel = cJSON_GetObjectItemCaseSensitive(data, prev);
	if(todel) cJSON_DeleteItemFromObjectCaseSensitive(data, prev);
	cJSON_AddStringToObject(data, prev, (char*)m3ApiOffsetToPtr(value));

	json_to_file(json, fname);
	cJSON_Delete(json);
	m3ApiSuccess();
}
m3ApiRawFunction(nih_read_string)//passed path and pointer to output
{
	m3ApiGetArg(u32, path)
	m3ApiGetArg(u32, target)
	char* path_ptr = (char*)m3ApiOffsetToPtr(path);
	if(strlen(path_ptr) > 99)
		return m3Err_mallocFailed;//most relevant seeming error
	char path_str[100];
	strcpy(path_str, path_ptr);
	char fname[40];
	id_to_fname(fname, runtime);
	cJSON* json = file_to_json(fname);
	cJSON* data = cJSON_GetObjectItemCaseSensitive(json, "Data");
	char* prev = path_str;
	for(char* cur = path_str; *cur != '\0'; cur++)
		if(*cur == '.'){
			*cur = '\0';
			cJSON* next = cJSON_GetObjectItemCaseSensitive(data, prev);
			if(!cJSON_IsObject(next))
				return m3Err_mallocFailed;//most relevant seeming error
			data = next;//prepare for next iteration
			prev = cur + 1;
		}
	cJSON* next = cJSON_GetObjectItemCaseSensitive(data, prev);
	if(!cJSON_IsString(next))
		return m3Err_mallocFailed;//most relevant seeming error
	char* ret = (char*)malloc_runtime(strlen(next->valuestring)+1, runtime);
	strcpy(ret, next->valuestring);
	u32* y = (u32*)m3ApiOffsetToPtr(target);//offset to x
	*y = m3ApiPtrToOffset(ret);
	m3ApiSuccess();
}
m3ApiRawFunction(nih_execute_func)//passed machine, function name, param (and callback??)
{
	m3ApiSuccess();
}
char* exec(char* name, char* param, unsigned char* ID){
	for(int i = 0; i < machines.count(); i++){
		Machine cur = machines.peek(i);
		if(memcmp(ID, cur.ID, ID_len)==0){
			if(cur.local){
				return run_wasm(name, param, ID);
			}
			else{
				ESP_LOGI(nih, "running against %s", cur.IP);
				return nullptr;
			}
		}
	}
	throw std::runtime_error("could not find machine!");
}
//calling function has responsibility for cleaning up both parameter and return value!!!
char* run_wasm(char* name, char* param, unsigned char* ID)
{
	IM3Environment env = m3_NewEnvironment ();
	IM3Runtime runtime = m3_NewRuntime (env, 10*1024, NULL);

	list<key_value_pair<IM3Runtime, char*>>* params = *all_params.acquire();
	params->add(key_value_pair<IM3Runtime, char*>(runtime, param));
	all_params.release();
	list<key_value_pair<IM3Runtime, char*>>* ids = *all_ids.acquire();
	ids->add(key_value_pair<IM3Runtime, char*>(runtime, (char*)ID));
	all_ids.release();

	unsigned char* wasm;
	int wasm_length = load_wasm(ID, &wasm);

	IM3Module module;
	M3Result result = m3_ParseModule (env, &module, (uint8_t*)wasm, wasm_length - 1);
	delete wasm;
	if(result) ESP_LOGE(nih, "result 1:%s", result);
	result = m3_LoadModule (runtime, module);
	if(result) ESP_LOGE(nih, "result 2:%s", result);
	result = m3_LinkRawFunction (module, "nih", "getParam", "v(*)", &nih_get_param);
	//if(result) ESP_LOGE(nih, "result 3:%s", result);
	result = m3_LinkRawFunction (module, "nih", "setReturn", "v(*)", &nih_return);
	//if(result) ESP_LOGE(nih, "result 4:%s", result);
	result = m3_LinkRawFunction (module, "nih", "mallocWasm", "v(*i)", &nih_malloc);
	//if(result) ESP_LOGE(nih, "result 5:%s", result);
	result = m3_LinkRawFunction (module, "nih", "writeString", "v(**)", &nih_write_string);
	//if(result) ESP_LOGE(nih, "result 6:%s", result);
	result = m3_LinkRawFunction (module, "nih", "readString", "v(**)", &nih_read_string);
	//if(result) ESP_LOGE(nih, "result 7:%s", result);
	IM3Function func;
	char fullname[120];
	strcpy(fullname, "wrapper_");
	strcpy(fullname + strlen(fullname), name);
	result = m3_FindFunction (&func, runtime, fullname);
	if(result) ESP_LOGE(nih, "result 8:%s", result);
	const char* char_args[] = { NULL };
	result = m3_CallWithArgs (func, 0, char_args);
	if(result) ESP_LOGE(nih, "result 9:%s", result);
	//cleanup/return:
	list<key_value_pair<IM3Runtime, char*>>* rets = *all_rets.acquire();
	char* ret = popPair(rets, runtime);
	all_rets.release();
	ids = *all_ids.acquire();
	popPair(ids, runtime);
	all_ids.release();

	
	m3_FreeRuntime(runtime);
	m3_FreeEnvironment(env);

	

	return ret;
}