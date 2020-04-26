#include "Nihilo.h"
#include "nvs_flash.h"
#include "esp_spiffs.h"
#include "esp_http_client.h"
#include <cstring>

#include "esp_wifi.h"
#include "freertos/task.h"

int rng(void* state, unsigned char* outbytes, size_t len){
	esp_fill_random(outbytes, len);
	return 0;
}

void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer){
	for(int i = 0; i < bytes_len; i++)
		snprintf(hexbuffer + (i*2), 3, "%02X", bytes[i]);
}
void hex_to_bytes(char* hexbuffer, unsigned char* bytes){
	for(int i = 0; i < strlen(hexbuffer)/2; i++){
		unsigned int val;
		sscanf(hexbuffer + (i*2), "%02X", &val);
		bytes[i] = (unsigned char)val;
	}
}

void json_to_file(cJSON* towrite, const char* path){
	FILE* file = fopen(path, "w");
	char* str = cJSON_Print(towrite);
	fwrite(str, 1, strlen(str), file);
	delete str;
	fflush(file);
	fclose(file);
}

cJSON* file_to_json(const char* path){
	FILE* file = fopen(path, "r");
	int root_len = 0;
	while(fgetc(file) != EOF) root_len++;
	fseek(file, 0, SEEK_SET);
	char* file_json = (char*)malloc(root_len + 1);
	fread(file_json, 1, root_len, file);
	fclose(file);
	cJSON* json = cJSON_Parse(file_json);
	delete file_json;
	return json;
}

void init_flash(){
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
}

//FROM HERE ON ARE INIT-ONLY FUNCTIONS, NOT THREAD SAFE

//netif is the cause of my grief
//modified from (and heavily based on) https://github.com/espressif/esp-idf/blob/741960d/examples/wifi/getting_started/station/main/station_example_main.c
void init_wifi()
{
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_sta();
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
}

bool wifi_connect_finished = false;
ip_event_got_ip_t connect_info;

void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
	if(event_base == WIFI_EVENT){
		esp_wifi_connect();
	}
	else if(event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP){
		connect_info = *(ip_event_got_ip_t*) event_data;
		wifi_connect_finished = true;
	}
}

ip_event_got_ip_t connect_wifi(const char* ssid, const char* psk){
	//register event handlers:
	esp_event_handler_instance_t instance_any_id;
	esp_event_handler_instance_t instance_got_ip;
	ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
	ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));
	//begin connection:
	wifi_config_t wifi_config = {0};
	strcpy((char*)wifi_config.sta.ssid, ssid);
	strcpy((char*)wifi_config.sta.password, psk);
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
	ESP_ERROR_CHECK(esp_wifi_start());
	//wait to be connected:
	
	while (!wifi_connect_finished)
		vTaskDelay(10/portTICK_PERIOD_MS);
	//unregister event handlers:
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
	return connect_info;
}

bool register_finished = false;

esp_err_t http_register_handler(esp_http_client_event_t *event){
	if(event->event_id == HTTP_EVENT_ON_FINISH)
		register_finished = true;
	return ESP_OK;
}
//not thread-safe
void register_machine(ip_event_got_ip_t ip_info, char* pub_hex){
	char url[100];
	snprintf(url, sizeof(url), "http://" IPSTR "/", IP2STR(&ip_info.ip_info.gw));
	//ESP_LOGI(nih, "Url: %s", url);
	char body[200];
	snprintf(body, sizeof(body), IPSTR ":%s", IP2STR(&ip_info.ip_info.ip), pub_hex);
	//ESP_LOGI(nih, "Body: %s", body);
	esp_http_client_config_t request = {
		.url = url,
		.method = HTTP_METHOD_POST,
		.event_handler = http_register_handler
	};
	esp_http_client_handle_t client = esp_http_client_init(&request);
	esp_http_client_set_post_field(client, body, strlen(body));
	register_finished = false;
	ESP_ERROR_CHECK(esp_http_client_perform(client));
	while (!register_finished)
		vTaskDelay(10/portTICK_PERIOD_MS);
	esp_http_client_cleanup(client);
}

bool get_machines_finished = false;
char* machine_return_raw;
esp_err_t http_get_machines_handler(esp_http_client_event_t *event){
	if(event->event_id == HTTP_EVENT_ON_FINISH){ 
		get_machines_finished = true;}
	else if(event->event_id == HTTP_EVENT_ON_DATA){
		int content_len = esp_http_client_get_content_length(event->client);
		machine_return_raw = (char*)malloc(content_len+1);
		memcpy(machine_return_raw, event->data, content_len);
		machine_return_raw[content_len] = 0;
	}
	return ESP_OK;
}

void load_non_local(ip_event_got_ip_t ip_info, list<Machine>* list){
	char url[100];
	snprintf(url, sizeof(url), "http://" IPSTR "/", IP2STR(&ip_info.ip_info.gw));
	esp_http_client_config_t request = {
		.url = url,
		.method = HTTP_METHOD_GET,
		.event_handler = http_get_machines_handler
	};
	esp_http_client_handle_t client = esp_http_client_init(&request);
	get_machines_finished = false;
	ESP_ERROR_CHECK(esp_http_client_perform(client));
	while (!get_machines_finished)
		vTaskDelay(10/portTICK_PERIOD_MS);
	esp_http_client_cleanup(client);
	char* prev = machine_return_raw;
	for(char* cur = machine_return_raw; *cur != '\0'; cur++)
		if(*cur == '\n'){
			*cur = '\0';
			if(prev != machine_return_raw)//skip the first one
				list->add(Machine(prev));
			prev = cur + 1;
		}
	if(strlen(prev) > 3)
		list->add(Machine(prev));
	delete machine_return_raw;
}

Machine load_from_memory(char* id_str) {
	char fname[40];
	snprintf(fname, sizeof(fname), "/%s.json", id_str);
	cJSON* root_mach = file_to_json((const char*)fname);
	Machine ret(root_mach);
	cJSON_Delete(root_mach);
	return ret;
}

/*void id_to_fname(char* fname, IM3Runtime runtime){
	ESP_LOGI(nih, "locking");
	list<key_value_pair<IM3Runtime, char*>>* ids = *all_ids.acquire();
	char* id = popPair(ids, runtime);
	ids->add(key_value_pair<IM3Runtime, char*>(runtime, id));
	all_ids.release();
	fname[0] = '/';
	bytes_to_hex((unsigned char*)id, ID_len, fname+1);
	strcpy(fname+strlen(fname), ".json");
	ESP_LOGI(nih, "%s", fname);
}*/

void save_wasm(unsigned char* ID, unsigned char* wasm, int len){
	char fname[40];
	fname[0] = '/';
	bytes_to_hex((unsigned char*)ID, ID_len, fname+1);
	strcpy(fname+strlen(fname), ".wasm");
	FILE* file = fopen(fname, "w");
	char* str = cJSON_Print(towrite);
	fwrite(wasm, 1, len, file);
	delete str;
	fflush(file);
	fclose(file);
}
int load_wasm(unsigned char* ID, unsigned char** wasm){

}