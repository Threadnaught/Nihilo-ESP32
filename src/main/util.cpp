#include "Nihilo.h"
#include "nvs_flash.h"
#include "esp_spiffs.h"
#include <cstring>

#include "esp_wifi.h"
#include "freertos/task.h"

bool done = false;
ip_event_got_ip_t connect_info;

int rng(void* state, unsigned char* outbytes, size_t len){
	esp_fill_random(outbytes, len);
	return 0;
}

void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer){
	for(int i = 0; i < bytes_len; i++)
		snprintf(hexbuffer + (i*2), 3, "%02X", bytes[i]);
}

void json_to_file(cJSON* towrite, const char* path){
	FILE* file = fopen(path, "w");
	char* str = cJSON_Print(towrite);
	//ESP_LOGI(nih, "writing %s", str);
	fwrite(str, 1, strlen(str), file);
	delete str;
	fflush(file);
	fclose(file);
}

//netif is the cause of my grief
//modified from (and heavily based on) https://github.com/espressif/esp-idf/blob/741960d/examples/wifi/getting_started/station/main/station_example_main.c
void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
	if(event_base == WIFI_EVENT){
		esp_wifi_connect();
	}
	else if(event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP){
		connect_info = *(ip_event_got_ip_t*) event_data;
		ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
		done = true;
	}
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

void init_wifi()
{
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());
	esp_netif_create_default_wifi_sta();
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
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
	ESP_ERROR_CHECK(esp_wifi_start() );
	//wait to be connected:
	while (!done)
		vTaskDelay(10/portTICK_PERIOD_MS);
	//unregister event handlers:
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
	ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
	return connect_info;
}

void register_root(ip_event_got_ip_t ip_info, unsigned char* root_pub){
	esp_http_client_config_t request = {
		.url = "http://httpbin.org/redirect/2",
		.event_handler = _http_event_handle,
	};
}