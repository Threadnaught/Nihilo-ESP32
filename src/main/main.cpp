#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "esp_wifi.h"
#include "esp32/sha.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"

//#include <WiFiClient.h>
//#include <WebServer.h>

#include <atomic>

#include "esp_system.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_spiffs.h"

#include "cJSON.h"

//deps from wasm:
/*
#include "wasm3.h"
#include "m3_env.h"

#include "extra/fib32.wasm.h"

#include <time.h>
*/

#define ID_len 16 //bytes
#define rsa_key_len 512
#define rsa_key_bits rsa_key_len * 8
#define ecc_pub_len 32
#define tag "nih"


template <typename T> struct ListElem{
	T element;
	ListElem<T>* next;
	ListElem(){}
	ListElem(T item){
		element = item;
	}
};
template <typename T> struct List{
	std::atomic_flag mutex = ATOMIC_FLAG_INIT;
	ListElem<T>* first = NULL;
	void add(T toadd){
		lock_mutex();
		if(first==NULL){
			first = new ListElem<T>(toadd);
			unlock_mutex();
			return;
		}
		ListElem<T>* cur = first;
		while(cur->next != NULL)cur = cur->next;
		cur->next = new ListElem<T>(toadd);
		unlock_mutex();
	}
	int count(){
		lock_mutex();
		if(first == NULL){
			unlock_mutex();
			return 0;
		}
		ListElem<T>* cur = first;
		int i = 0;
		for(;cur->next != NULL;i++,cur = cur->next);
		unlock_mutex();
		return i+1;
	}
	T peek(int index=-1){
		lock_mutex();
		//if index is -1, peek at end
		if(index==-1)
			index=count();
		//if empty, use this hack to get the default:
		if(first == NULL) {
			unlock_mutex();
			//hack to get default value
			ListElem<T> hack;
			return hack.element;
		}
		ListElem<T>* cur = first;
		for(int i = 0; i < index; i++)cur=cur->next;
		T ret = cur->element;
		unlock_mutex();
		return ret;
	}
	T pop(int index = -1){
		lock_mutex();
		if(index==-1)
			index=count()-1;
		if(index == 0){
			ListElem<T>* todel_first = first;
			first = first->next;
			T ret_first = todel_first->element;
			delete todel_first;
			unlock_mutex();
			return ret_first;
		}
		ListElem<T>* cur = first;
		for(int i = 0; i < index-1; i++)
			cur=cur->next;
		ListElem<T>* todel = cur->next;
		T ret = todel->element;
		cur->next = cur->next->next;
		delete todel;
		unlock_mutex();
		return ret;
	}
	void lock_mutex(){
		while (mutex.test_and_set(std::memory_order_acquire));
	}
	void unlock_mutex(){
		mutex.clear(std::memory_order_release); 
	}
};

struct Machine{
	char ID_str[(ecc_pub_len*2)+1];
	bool local;
	unsigned char ecc_pub[ecc_pub_len];
	//unsigned char ecc_priv[ecc];
};

List<Machine> machines;

bool check_safe(char* sender_id, char* target_id){
	return true;
}

cJSON* read_json(char* sender_id, char* target_id, bool safe=false){
	if(!check_safe(sender_id, target_id))return NULL;
	return NULL;
}
void write_json(char* sender_id, char* target_id, cJSON* json, bool safe=false){
	if(!check_safe(sender_id, target_id)) return;
}
char* execute(char* sender_id, char* target_id, const char* name, char* param, bool safe=false){
	if(!check_safe(sender_id, target_id)) return NULL;
	return NULL;
}

cJSON* read_path(cJSON* m, char* path){
	char readbuf[50];
	int readpos = 0;
	cJSON* cur = m;
	for(int i = 0; i < strlen(path); i++){
		if(path[i] != '.'){
			if(readpos == 50) return NULL;
			readbuf[readpos++]=path[i];
		}
		readbuf[readpos] = '\0';
		cur = cJSON_GetObjectItemCaseSensitive(cur, readbuf);
		if(cur == NULL) return NULL;
		readpos = 0;
	}
	return cur;
}
//void write_path(cJSON* m, char* path, cJSON* to_write){}

//wasm_read_str
//wasm_write_str
//wasm_read_int
//wasm_write_int
//wasm_read_float
//wasm_write_float
//wasm_read_bool
//wasm_write_bool

void handle_http_message(){}

void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer){
	for(int i = 0; i < bytes_len; i++)
		snprintf(hexbuffer + (i*2), 3, "%02x", bytes[i]);
}

int rng(void* state, unsigned char* outbytes, size_t len){
	esp_fill_random(outbytes, len);
	return 0;
}

Machine new_machine_ecc(){//create eliptic curve machine
	mbedtls_ecdh_context ecc_ctxt;
	//init ecdh/curves:
	mbedtls_ecdh_init(&ecc_ctxt);
	mbedtls_ecp_group_load(&ecc_ctxt.grp, MBEDTLS_ECP_DP_CURVE25519);
	//create public:
	mbedtls_ecdh_gen_public(&ecc_ctxt.grp, &ecc_ctxt.d, &ecc_ctxt.Q, rng, NULL);
	unsigned char pub_buf[ecc_pub_len];
	mbedtls_mpi_write_binary(&ecc_ctxt.Q.X, pub_buf, ecc_pub_len); 
	unsigned char pub_digest[32];
	esp_sha(SHA2_256, pub_buf, ecc_pub_len, pub_digest);
	//copy into machine:
	Machine ret;
	memcpy(ret.ID_str, pub_digest, ID_len);
	mbedtls_ecdh_free(&ecc_ctxt);
	return ret;
}

extern "C" void app_main(void)
{
	ESP_LOGI(tag, "Nihilo init start");
	//begin init filesystem:
	esp_vfs_spiffs_conf_t conf = {
		.base_path = "/spiffs",
		.partition_label = NULL,
		.max_files = 5,
		.format_if_mount_failed = true
	};
	if(esp_vfs_spiffs_register(&conf) != ESP_OK){
		ESP_LOGE(tag, "SPIFFS init failure");
		return;
	}
	//init wifi (and enable trueish RNG):
	wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
	esp_wifi_init(&init_cfg);
	esp_wifi_set_mode(WIFI_MODE_STA);
	esp_wifi_start();
	while(true){
		Machine m = new_machine_ecc();
		char hexbuf[(ID_len*2)+1];
		for(int i = 0; i < ID_len; i++)
			snprintf(hexbuf + (i*2), 3, "%02x", m.ID_str[i]);
		ESP_LOGI(tag, "Created Machine %s", hexbuf);
	}
	return;
	//load root file:
	FILE* root_file = fopen("/spiffs/root.json", "r");
	if(root_file == NULL){
		ESP_LOGI(tag, "Recreating FS");
		esp_spiffs_format("storage");
		ESP_LOGI(tag, "Formatted FS, recreating root");
		//create root json
		cJSON* write_root = cJSON_CreateObject();
		cJSON_AddStringToObject(write_root, "WiFi_SSID", "test");
		cJSON_AddStringToObject(write_root, "WiFi_PSK", "thisisnotagoodpassword");
		FILE* write_root_file = fopen("/spiffs/root.json", "w");
		char* root_json = cJSON_Print(write_root);
		cJSON_Delete(write_root);
		fwrite(root_json, 1, strlen(root_json), write_root_file);
		delete root_json;
		fflush(write_root_file);
		fclose(write_root_file);
		root_file = fopen("/spiffs/root.json", "r");
	}
	//load root json
	int root_len = 0;
	while(fgetc(root_file) != EOF) root_len++;
	fseek(root_file, 0, SEEK_SET);
	char* root_file_json = (char*)malloc(root_len + 1);
	fread(root_file_json, 1, root_len, root_file);
	fclose(root_file);
	cJSON* root = cJSON_Parse(root_file_json);
	delete root_file_json;
	//connect to wifi
	cJSON* ssid = cJSON_GetObjectItemCaseSensitive(root, "WiFi_SSID");
	cJSON* psk = cJSON_GetObjectItemCaseSensitive(root, "WiFi_PSK");
	if((!cJSON_IsString(ssid)) || (!cJSON_IsString(psk))){
		ESP_LOGE(tag, "Invalid WiFi creds!");
		return;
	}
	wifi_config_t wifi_cfg;
	strcpy((char*)wifi_cfg.sta.ssid, ssid->valuestring);
	strcpy((char*)wifi_cfg.sta.password, psk->valuestring);
	esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_cfg);
	if(esp_wifi_connect() != ESP_OK){
		ESP_LOGE(tag, "Wifi doesn't work!");
		return;
	}
	cJSON_Delete(root);
	//load machines
	//begin web server
	ESP_LOGI(tag, "Nihilo init successful");
}





/*
static void run_wasm(void)
{
	M3Result result = m3Err_none;

	uint8_t* wasm = (uint8_t*)fib32_wasm;
	uint32_t fsize = fib32_wasm_len-1;

	printf("Loading WebAssembly...\n");
	IM3Environment env = m3_NewEnvironment ();
	if (!env) FATAL("m3_NewEnvironment failed");

	IM3Runtime runtime = m3_NewRuntime (env, 1024, NULL);
	if (!runtime) FATAL("m3_NewRuntime failed");

	IM3Module module;
	result = m3_ParseModule (env, &module, wasm, fsize);
	if (result) FATAL("m3_ParseModule: %s", result);

	result = m3_LoadModule (runtime, module);
	if (result) FATAL("m3_LoadModule: %s", result);

	IM3Function f;
	result = m3_FindFunction (&f, runtime, "fib");
	if (result) FATAL("m3_FindFunction: %s", result);

	printf("Running...\n");

	const char* i_argv[2] = { "24", NULL };
	result = m3_CallWithArgs (f, 1, i_argv);

	if (result) FATAL("m3_CallWithArgs: %s", result);

	long value = *(uint64_t*)(runtime->stack);
	printf("Result: %ld\n", value);
}*/