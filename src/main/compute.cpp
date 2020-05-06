#include "Nihilo.h"

#include "wasm3.h"
#include "m3_env.h"
#include "m3_api_defs.h"
#include "esp_err.h"

#define heap_offset 0x8000//how far is heap from stack

//locker<list<key_value_pair<IM3Runtime, char*>>*> all_params(new list<key_value_pair<IM3Runtime, char*>>());
//locker<list<key_value_pair<IM3Runtime, char*>>*> all_rets(new list<key_value_pair<IM3Runtime, char*>>());
//locker<list<key_value_pair<IM3Runtime, char*>>*> all_ids(new list<key_value_pair<IM3Runtime, char*>>());

//locker<list<char**>*> task_queue(new list<char**>());
locker<list<task*>*> task_queue(new list<task*>());
locker<list<key_value_pair<IM3Runtime, task*>>*> cur_tasks(new list<key_value_pair<IM3Runtime, task*>>());

task* popTask(list<key_value_pair<IM3Runtime, task*>>* list, IM3Runtime target){
	for(int i = 0; i < list->count(); i++){
		auto kvp = list->peek(i);
		if (kvp.key == target){
			list->pop(i);
			return kvp.value;
		}
	}
	return nullptr;
}
task* getTask(list<key_value_pair<IM3Runtime, task*>>* list, IM3Runtime target){
	task* ret = popTask(list, target);
	list->add(key_value_pair<IM3Runtime, task*>(target, ret));
	return ret;
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
	list<key_value_pair<IM3Runtime, task*>>* params = *cur_tasks.acquire();
	task* cur_task = getTask(params, runtime);
	cur_tasks.release();
	char* cur_param = (char*)(cur_task+1);
	u32* y = (u32*)m3ApiOffsetToPtr(param);//offset to x
	char* target = (char*)malloc_runtime(strlen(cur_param)+1, runtime);
	strcpy(target, cur_param);
	*y = m3ApiPtrToOffset(target);
	m3ApiSuccess();
}

m3ApiRawFunction(nih_return)
{
	m3ApiGetArg(u32, param)
	if(param == 0)//do nothing if returns nullptr
		m3ApiSuccess();
	char* src = (char*)m3ApiOffsetToPtr(param);
	size_t len = strnlen(src, 999); //truncates return value at 1000 chars
	char* dest = (char*)malloc(len+1);
	memcpy(dest, src, len+1);
	list<key_value_pair<IM3Runtime, task*>>* tasks = *cur_tasks.acquire();
	task* t = getTask(tasks, runtime);//pop if runtime already has returned (cheeky)
	if(t->ret != nullptr)
		delete t->ret;
	t->ret = dest;
	cur_tasks.release();
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
	list<key_value_pair<IM3Runtime, task*>>* tasks = *cur_tasks.acquire();
	task* task = getTask(tasks, runtime);
	cur_tasks.release();
	fname[0] = '/';
	bytes_to_hex(task->dest_pub, ID_len, fname+1);
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
m3ApiRawFunction(nih_get_known)
{
	m3ApiReturnType(int32_t);
	m3ApiGetArg(u32, IdsOut);
	m3ApiGetArg(int, include_local);
	m3ApiGetArg(int, include_non_local);
	list<Machine> machine_list;
	for(int i = 0; i < machines.count(); i++){
		Machine m = machines.peek(i);
		if((include_local && m.local) || (include_non_local && !m.local))
			machine_list.add(m);
	}
	unsigned char* toret = (unsigned char*)malloc_runtime(ecc_pub_len * machine_list.count(), runtime);
	for(int i = 0; i < machine_list.count(); i++){
		memcpy(toret + (i*ecc_pub_len), machine_list.peek(i).ecc_pub, ecc_pub_len);
	}
	u32* y = (u32*)m3ApiOffsetToPtr(IdsOut);//offset to x
	*y = m3ApiPtrToOffset(toret);
	m3ApiReturn(machine_list.count());
}
m3ApiRawFunction(nih_log)
{
	m3ApiGetArg(u32, tolog)
	ESP_LOGI(nih, "%s", (char*)m3ApiOffsetToPtr(tolog));
	m3ApiSuccess();
}
m3ApiRawFunction(nih_queue)//void queue(const unsigned char* target_pub, const char* fname, const char* param, const char* onsuccess, const char* onfail);
{
	/*m3ApiGetArg(u32, target_pub_offset);
	m3ApiGetArg(u32, fname_offset);
	m3ApiGetArg(u32, param_offset);
	m3ApiGetArg(u32, onsuccess_offset);
	m3ApiGetArg(u32, onfail_offset);
	const unsigned char* target_pub = (unsigned char*)m3ApiOffsetToPtr(target_pub_offset);
	const char* fname = (char*)m3ApiOffsetToPtr(fname_offset);
	const char* param = (char*)m3ApiOffsetToPtr(param_offset);
	const char* onsuccess = (char*)m3ApiOffsetToPtr(onsuccess_offset);
	const char* onfail = (char*)m3ApiOffsetToPtr(onfail_offset);*/
	m3ApiSuccess();
}
#define checkerr(result, stage) if(result) {\
	popTask(*cur_tasks.acquire(), runtime); cur_tasks.release();\
	m3_FreeRuntime(runtime); \
	m3_FreeEnvironment(env); \
	ESP_LOGE(nih, "error at %s", stage);\
	throw std::runtime_error(result);\
}
//calling function has responsibility for cleaning up both parameter and return value!!!
char* run_wasm(task* t, unsigned char* ID)
{
	IM3Environment env = m3_NewEnvironment ();
	IM3Runtime runtime = m3_NewRuntime (env, 5*1024, nullptr);

	list<key_value_pair<IM3Runtime, task*>>* tasks = *cur_tasks.acquire();
	tasks->add(key_value_pair<IM3Runtime, task*>(runtime, t));
	cur_tasks.release();

	unsigned char* wasm;
	int wasm_length = load_wasm(ID, &wasm);

	IM3Module module;
	M3Result result = m3_ParseModule (env, &module, (uint8_t*)wasm, wasm_length - 1);
	delete wasm;
	checkerr(result, "parse");
	result = m3_LoadModule (runtime, module);
	checkerr(result, "load");
	result = m3_LinkRawFunction (module, "nih", "getParam", "v(*)", &nih_get_param);
	result = m3_LinkRawFunction (module, "nih", "setReturn", "v(*)", &nih_return);
	result = m3_LinkRawFunction (module, "nih", "mallocWasm", "v(*i)", &nih_malloc);
	result = m3_LinkRawFunction (module, "nih", "writeString", "v(**)", &nih_write_string);
	result = m3_LinkRawFunction (module, "nih", "readString", "v(**)", &nih_read_string);
	result = m3_LinkRawFunction (module, "nih", "knownIds", "i(*ii)", &nih_get_known);
	result = m3_LinkRawFunction (module, "nih", "log", "v(*)", &nih_log);
	IM3Function func;
	char fullname[120];
	strcpy(fullname, "wrapper_");
	strcpy(fullname + strlen(fullname), t->t.function_name);
	result = m3_FindFunction (&func, runtime, fullname);
	checkerr(result, "find");
	const char* char_args[] = { nullptr };
	result = m3_CallWithArgs (func, 0, char_args);
	checkerr(result, "call");
	//cleanup/return:
	tasks = *cur_tasks.acquire();
	char* ret = popTask(tasks, runtime)->ret;
	cur_tasks.release();
	m3_FreeRuntime(runtime);
	m3_FreeEnvironment(env);
	return ret;
}

//queue takes ownership of passed variables
void queue_task(task* t){
	list<task*>* tasks = *task_queue.acquire();
	tasks->add(t);
	task_queue.release();
}
void queue_copy(const unsigned char* origin_pub, const unsigned char* dest_pub, const char* funcname, const char* param, const char* onsuccess, const char* onfailure){
	task inited_task;//to get init vars
	task* t = (task*)malloc(sizeof(task) + (param==nullptr?0:strlen(param)) + 1);
	memcpy(t, &inited_task, sizeof(task));
	memcpy(t->origin_pub, origin_pub, ecc_pub_len);
	memcpy(t->dest_pub, dest_pub, ecc_pub_len);
	strncpy(t->t.function_name, funcname, max_func_len-1);
	memset(t->t.on_success, 0, max_func_len);
	memset(t->t.on_failure, 0, max_func_len);
	memset((char*)(t+1), 0, 1);
	if(onsuccess != nullptr)
		strncpy(t->t.on_success, onsuccess, max_func_len-1);
	if(onfailure != nullptr)
		strncpy(t->t.on_failure, onfailure, max_func_len-1);
	if(param != nullptr)
		strcpy((char*)(t+1), param);
	queue_task(t);
}

void exec(task* t){
	//ESP_LOGI(nih, "execing %s(%s), %s, %s", t->t.function_name, (char*)(t+1), t->t.on_success, t->t.on_failure);
	for(int i = 0; i < machines.count(); i++){
		Machine m = machines.peek(i);
		if(memcmp(t->dest_pub, m.ecc_pub, ecc_pub_len) == 0){
			if(m.local){
				try{
					char* response = run_wasm(t, m.ID);
					if(strlen(t->t.on_success) > 0)
						queue_copy(t->dest_pub, t->origin_pub, t->t.on_success, response, nullptr, nullptr);
					if(response != nullptr) 
						delete response;
				}
				catch (const std::exception& e) {
					ESP_LOGE(nih, "execution exception in function %s: %s", t->t.function_name, e.what());
					if(strlen(t->t.on_failure) > 0)
						queue_copy(t->dest_pub, t->origin_pub, t->t.on_failure, "execution exception", nullptr, nullptr);
				}
				return;
			}
			else{
				for(int j = 0; j < machines.count(); j++){
					Machine origin = machines.peek(j);
					if(memcmp(t->origin_pub, origin.ecc_pub, ecc_pub_len) == 0){
						send_call(origin, m, t->t.function_name, (char*)(t+1), t->t.on_success, t->t.on_failure);
						return;
					}
				}
				throw std::runtime_error("Could not find origin machine");
			}
		}
	}
	//target machine checks will have already been applied, so there is no way to trigger this exception remotley
	throw std::runtime_error("Could not find destination machine");
}

void empty_queue(){
	//acquire the queue:
	list<task*>* tasks = *task_queue.acquire();
	while(tasks->count() > 0){
		//remove 0th queue item:
		task* this_task = tasks->pop(0);
		//release the queue so other threads (or this thread) can use it
		task_queue.release();
		//exec((unsigned char*)this_task[0], (unsigned char*)this_task[1], this_task[2], this_task[3], this_task[4], this_task[5]);
		exec(this_task);
		//tidy up memory:
		delete this_task;
		//acquire for the next iteration:
		tasks = *task_queue.acquire();
	}
	task_queue.release();
}