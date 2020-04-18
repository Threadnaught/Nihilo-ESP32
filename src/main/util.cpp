#include "Nihilo.h"
#include <cstring>

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
	ESP_LOGI(nih, "writing %s", str);
	fwrite(str, 1, strlen(str), file);
	delete str;
	fflush(file);
	fclose(file);
}
