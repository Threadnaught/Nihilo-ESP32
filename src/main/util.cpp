#include "Nihilo.h"

int rng(void* state, unsigned char* outbytes, size_t len){
	esp_fill_random(outbytes, len);
	return 0;
}

void bytes_to_hex(unsigned char* bytes, int bytes_len, char* hexbuffer){
	for(int i = 0; i < bytes_len; i++)
		snprintf(hexbuffer + (i*2), 3, "%02X", bytes[i]);
}

