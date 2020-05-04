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
#include "esp_err.h"

#include "root.wasm.h"

list<Machine> machines;

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

//wasm_read_str
//wasm_write_str

Machine new_machine(){//create eliptic curve machine
	mbedtls_ecdh_context ecc_ctxt;
	//init ecdh/curves:
	mbedtls_ecdh_init(&ecc_ctxt);
	mbedtls_ecp_group_load(&ecc_ctxt.grp, MBEDTLS_ECP_DP_CURVE25519);
	//create public:
	mbedtls_ecdh_gen_public(&ecc_ctxt.grp, &ecc_ctxt.d, &ecc_ctxt.Q, rng, NULL);
	//Machine ret(ecc_ctxt.Q, ecc_ctxt.d);
	Machine ret(&ecc_ctxt.grp, &ecc_ctxt.Q, &ecc_ctxt.d);
	mbedtls_ecdh_free(&ecc_ctxt);
	cJSON* machine_json = cJSON_CreateObject();
	char pub[(ecc_pub_len*2)+1];
	char priv[(ecc_priv_len*2)+1];
	bytes_to_hex(ret.ecc_pub, ecc_pub_len, pub);
	bytes_to_hex(ret.ecc_priv, ecc_priv_len, priv);
	cJSON_AddStringToObject(machine_json, "Pub", pub);
	cJSON_AddStringToObject(machine_json, "Priv", priv);
	cJSON_AddItemToObject(machine_json, "Data", cJSON_CreateObject());
	char fname[sizeof(ret.ID_str)+10];
	snprintf(fname, sizeof(fname), "/%s.json", ret.ID_str);
	json_to_file(machine_json, fname);
	cJSON_Delete(machine_json);
	return ret;
}

/*Machine find_machine(unsigned char* pub){//find machine (LOCAL OR NON-LOCAL)

}*/

void init()
{
	ESP_LOGI(nih, "Nihilo init start");
	init_flash();
	init_wifi();
	//load root file:
	FILE* root_file = fopen("/root.json", "r");
	if(root_file == NULL){
		ESP_LOGI(nih, "Recreating FS. If the FS is full, you may need to run idf.py erase_flash");
		//create root json
		cJSON* write_root = cJSON_CreateObject();
		cJSON_AddStringToObject(write_root, "WiFi_SSID", "test");
		cJSON_AddStringToObject(write_root, "WiFi_PSK", "thisisnotagoodpassword");
		Machine root = new_machine();
		cJSON_AddStringToObject(write_root, "Root", root.ID_str);
		json_to_file(write_root, "/root.json");
		cJSON_Delete(write_root);
	}
	else{
		fclose(root_file);
	}
	cJSON* root = file_to_json("/root.json");
	//connect to wifi
	cJSON* ssid = cJSON_GetObjectItemCaseSensitive(root, "WiFi_SSID");
	cJSON* psk = cJSON_GetObjectItemCaseSensitive(root, "WiFi_PSK");
	if((!cJSON_IsString(ssid)) || (!cJSON_IsString(psk))){
		ESP_LOGE(nih, "Invalid WiFi creds!");
		return;
	}
	ESP_LOGI(nih, "connecting...");
	ip_event_got_ip_t ip_info = connect_wifi(ssid->valuestring, psk->valuestring);
	ESP_LOGI(nih, "connected");
	//load root:
	machines.add(load_from_memory(cJSON_GetObjectItemCaseSensitive(root, "Root")->valuestring));
	//update latest wasm:
	save_wasm(machines.peek(0).ID, (uint8_t*)root_opt_wasm, root_opt_wasm_len);
	//find all machines:
	char root_pub[(ecc_pub_len*2)+1];
	bytes_to_hex(machines.peek(0).ecc_pub, ecc_pub_len, root_pub);
	register_machine(ip_info, root_pub);
	load_non_local(ip_info, &machines);
	/*for(int i = 0; i < machines.count(); i++){
		Machine cur = machines.peek(i);
		ESP_LOGI(nih, "machine:%s:%s", cur.IP, cur.ID_str);
	}*/
	//cleanup:
	cJSON_Delete(root);
	ESP_LOGI(nih, "Nihilo init successful");
}

extern "C" void app_main(void)
{
	try{
		init();
		/*ESP_LOGI(nih, "machine count:%i", machines.count());
		if(machines.count() == 1){
			serve();
		}
		else
			send_call(machines.peek(0), machines.peek(1), nullptr, nullptr, nullptr, nullptr);
		return;*/
		queue_copy(machines.peek(0).ecc_pub, machines.peek(0).ecc_pub, "errrrrrr", "hello, world", "success", "error");
		empty_queue();
	}
	catch (const std::exception& e) {
		ESP_LOGE(nih, "Exception encountered:%s", e.what());
	}
}