#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "Nihilo.h"

#include "esp_wifi.h"
#include "esp32/sha.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "nvs_flash.h"

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



struct Machine{
	unsigned char ID[ID_len];
	char ID_str[(ID_len*2)+1];
	unsigned char ecc_pub[ecc_pub_len];
	bool local;
	bool root;
	bool is_public;
	unsigned char ecc_priv[ecc_priv_len];
	void calc_ID(){
		unsigned char pub_digest[32];
		esp_sha(SHA2_256, ecc_pub, ecc_pub_len, pub_digest);
		memccpy(ID, pub_digest, 1, ID_len);
		bytes_to_hex(ID, ID_len, ID_str);
	}
	Machine(){}
	Machine(unsigned char* pub){
		memcpy(ecc_pub, pub, ecc_pub_len);
		calc_ID();
		local = false;
	}
	Machine(mbedtls_ecp_group* grp, mbedtls_ecp_point* pub){
		if(mbedtls_mpi_write_binary(&pub->X, ecc_pub, ecc_pub_len) != 0)
			throw std::runtime_error("wrong number of bytes written to buffer");
		calc_ID();
		local = false;
	}
	Machine(mbedtls_ecp_group* grp, mbedtls_ecp_point* pub, mbedtls_mpi* priv) : Machine(grp, pub){
		mbedtls_mpi_write_binary(priv, ecc_priv, ecc_priv_len);
		local = true;
	}
	void derive_shared(unsigned char* other_pub, unsigned char* secret_buf){//derive the shared secret of this machine(pub/priv) and another machine(pub)
		if(!local) throw std::runtime_error("derive_shared must be called against local machine");
		//create/load context:
		mbedtls_ecdh_context ecc_ctxt;
		mbedtls_ecdh_init(&ecc_ctxt);
		mbedtls_ecp_group_load(&ecc_ctxt.grp, MBEDTLS_ECP_DP_CURVE25519);
		//write pub:
		mbedtls_mpi_lset(&ecc_ctxt.Qp.Z, 1);
		mbedtls_mpi_read_binary(&ecc_ctxt.Qp.X, other_pub, ecc_pub_len);
		//write priv:
		mbedtls_mpi_read_binary(&ecc_ctxt.d, ecc_priv, ecc_priv_len);
		//create secret:
		mbedtls_ecdh_compute_shared(&ecc_ctxt.grp, &ecc_ctxt.z, &ecc_ctxt.Qp, &ecc_ctxt.d, rng, NULL);
		if(mbedtls_mpi_size(&ecc_ctxt.z) < shared_secret_len) throw std::runtime_error("secret too small");
		//write into secret_buf
		unsigned char intermediate_secret_buf[32];
		mbedtls_mpi_write_binary(&ecc_ctxt.z, intermediate_secret_buf, 32);
		memcpy(secret_buf, intermediate_secret_buf, shared_secret_len);
		//cleanup
		mbedtls_ecdh_free(&ecc_ctxt);
	}
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

/*cJSON* read_path(cJSON* m, char* path){
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
}*/
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

void json_to_file(cJSON* towrite, const char* path){
	FILE* file = fopen(path, "w");
	char* str = cJSON_Print(towrite);
	ESP_LOGI(nih, "writing %s", str);
	fwrite(str, 1, strlen(str), file);
	delete str;
	fflush(file);
	fclose(file);
}

Machine new_machine(bool Public=false){//create eliptic curve machine
	mbedtls_ecdh_context ecc_ctxt;
	//init ecdh/curves:
	mbedtls_ecdh_init(&ecc_ctxt);
	mbedtls_ecp_group_load(&ecc_ctxt.grp, MBEDTLS_ECP_DP_CURVE25519);
	//create public:
	mbedtls_ecdh_gen_public(&ecc_ctxt.grp, &ecc_ctxt.d, &ecc_ctxt.Q, rng, NULL);
	//Machine ret(ecc_ctxt.Q, ecc_ctxt.d);
	Machine ret(&ecc_ctxt.grp, &ecc_ctxt.Q, &ecc_ctxt.d);
	ret.is_public = Public;
	mbedtls_ecdh_free(&ecc_ctxt);
	cJSON* machine_json = cJSON_CreateObject();
	char pub[(ecc_pub_len*2)+1];
	char priv[(ecc_priv_len*2)+1];
	bytes_to_hex(ret.ecc_pub, ecc_pub_len, pub);
	bytes_to_hex(ret.ecc_priv, ecc_priv_len, priv);
	cJSON_AddStringToObject(machine_json, "Pub", pub);
	cJSON_AddStringToObject(machine_json, "Priv", priv);
	cJSON_AddBoolToObject(machine_json, "Public", Public);
	cJSON_AddItemToObject(machine_json, "Data", cJSON_CreateObject());
	char fname[sizeof(ret.ID_str)+10];
	snprintf(fname, sizeof(fname), "/%s.json", ret.ID_str);
	json_to_file(machine_json, fname);
	cJSON_Delete(machine_json);
	machines.add(ret);
	return ret;
}

//Machine find_machine(unsigned char* pub){//find machine (LOCAL OR NON-LOCAL)

//}

extern "C" void app_main(void)
{
	ESP_LOGI(nih, "Nihilo init start");
	//init nvs:
	ESP_ERROR_CHECK(nvs_flash_init());
	//begin init filesystem:
	esp_vfs_spiffs_conf_t conf = {
		.base_path = "",
		.partition_label = NULL,
		.max_files = 5,
		.format_if_mount_failed = true
	};
	ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));
	//init wifi (and enable trueish RNG):
	wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_start());
	//load root file:
	FILE* root_file = fopen("/root.json", "r");
	if(root_file == NULL){
		ESP_LOGI(nih, "Recreating FS. If the FS is full, you may need to run idf.py erase_flash");
		//create root json
		cJSON* write_root = cJSON_CreateObject();
		cJSON_AddStringToObject(write_root, "WiFi_SSID", "test");
		cJSON_AddStringToObject(write_root, "WiFi_PSK", "thisisnonihoodpassword");
		Machine root = new_machine(true);
		machines.pop();
		char root_pub[(ecc_pub_len*2)+1];
		bytes_to_hex(root.ecc_pub, ecc_pub_len, root_pub);
		cJSON_AddStringToObject(write_root, "Root", root_pub);
		json_to_file(write_root, "/root.json");
		cJSON_Delete(write_root);
		root_file = fopen("/root.json", "r");
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
		ESP_LOGE(nih, "Invalid WiFi creds!");
		return;
	}
	wifi_config_t wifi_cfg;
	strcpy((char*)wifi_cfg.sta.ssid, ssid->valuestring);
	strcpy((char*)wifi_cfg.sta.password, psk->valuestring);
	
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_cfg));
	ESP_ERROR_CHECK(esp_wifi_connect());
	//load all machines:
	ESP_LOGI(nih, "Loading root machine with pub %s", cJSON_GetObjectItemCaseSensitive(root, "Root")->valuestring);
	//begin server
	//cleanup:
	cJSON_Delete(root);
	ESP_LOGI(nih, "Nihilo init successful");
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